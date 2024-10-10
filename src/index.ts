import sqlite3 from "sqlite3";
import tough from "tough-cookie";
import crypto from "crypto";
import fs from "fs";

import type { Nullable, Callback, Cookie, MemoryCookieStoreIndex, MemoryCookieStore } from "tough-cookie";

const KEYLENGTH = 16;
const SALT = 'saltysalt';
const ITERATIONS = process.platform === 'darwin' ? 1003 : (process.platform === 'linux' ? 1 : undefined);

const pathIdentifiers = ['/', '\\'];

const isPathFormat = (profileOrPath:string) =>
	profileOrPath && 
	pathIdentifiers.some(pathIdentifier => profileOrPath.includes(pathIdentifier));

const domainSeen = new Set();

const getPath = (profileOrPath:string | undefined) => {
    if (profileOrPath && isPathFormat(profileOrPath)) {
        const path = caterForCookiesInPath(profileOrPath)
        if (!fs.existsSync(path)) {
            throw new Error(`Path: ${path} not found`);
        }

        return path;
    }

    const defaultProfile = 'Default';
    const profile = profileOrPath || defaultProfile;

    switch (process.platform) {
        case 'darwin': {
            return `${process.env.HOME}/Library/Application Support/Google/Chrome/${profile}/Cookies`;
        }

        case 'linux': {
            return `${process.env.HOME}/.config/google-chrome/${profile}/Cookies`;
        }

        case 'win32': {
            return `${process.env.USERPROFILE}\\AppData\\Local\\Google\\Chrome\\User Data\\${profile}\\Cookies`;
        }

        default: {
            throw new Error('Only Mac, Windows, and Linux are supported.');
        }
    }
}

const convertChromiumTimestampToUnix = (timestamp:number) => {
    return Number((BigInt(timestamp) - BigInt(11644473600000000n)) / 1000000n);
    // return int(timestamp.toString()).sub('11644473600000000').div(1000000);
}

const caterForCookiesInPath = (path:string) => {
	const cookiesFileName = 'Cookies'
	const includesCookies = path.slice(-cookiesFileName.length) === cookiesFileName

	if (includesCookies) {
		return path;
	}

    switch (process.platform) {
        case 'darwin':
        case 'linux': {
            return path.concat(`/${cookiesFileName}`);
        }

        case 'win32': {
            return path.concat(`\\${cookiesFileName}`);
        }

        default: {
            return path;
        }
    }
}

const decrypt = (key:Buffer, encryptedData:Buffer) => {
	const iv = Buffer.from(new Array(KEYLENGTH + 1).join(' '), 'binary');

	const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
	decipher.setAutoPadding(false);

	encryptedData = encryptedData.slice(3);

	let decoded = decipher.update(encryptedData);

	const final = decipher.final();
	final.copy(decoded, decoded.length - 1);

	const padding = decoded[decoded.length - 1];
	if (padding) {
		decoded = decoded.slice(0, decoded.length - padding);
	}

	return decoded.toString('utf8');
}

const getDerivedKey = async () => {
    switch (process.platform) {
        case 'darwin': {
            const keytar = await import('keytar');
            const chromePassword = await keytar.default.getPassword('Chrome Safe Storage', 'Chrome');

            if (!chromePassword) {
                throw new Error('Chrome password not found');
            }

            return crypto.pbkdf2Sync(chromePassword, SALT, ITERATIONS as number, KEYLENGTH, 'sha1');
        }
        case 'linux': {
            const chromePassword = 'peanuts';
            return crypto.pbkdf2Sync(chromePassword, SALT, ITERATIONS as number, KEYLENGTH, 'sha1');
        }

        case 'win32': {
            // @ts-ignore
            const dpapi = await import('win-dpapi');
            return null
        }

        default: {
            throw new Error('Unsupported platform');
        }
    }
}

export const injectChromeCookies = async (idx: MemoryCookieStoreIndex, profileOrPath?:string) => {
    const path = getPath(profileOrPath);
    const derivedKey = await getDerivedKey();

    const queryCookies = new Promise((resolve, reject) => {
        const db = new sqlite3.Database(path);
        db.serialize(() => {
            db.all(`SELECT * FROM cookies`, (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
        db.close();
    }) as Promise<any[]>;

    const cookies  = [] as tough.Cookie[];
    const rows = await queryCookies;    
    for (const row of rows) {
        if (row.encrypted_value.length === 0) {
            row.value = "";
        } else if (process.platform === 'win32') {
            // TODO: Implement decryption for Windows
            // @ts-ignore
            const decrypted = await dpapi.decryptData(cookie.encrypted_value);
        } else {
            const encryptedData = Buffer.from(row.encrypted_value, 'binary');
            row.value = decrypt(derivedKey as Buffer, encryptedData);
        }

        // console.log(row);
        const hostOnly = !row.host_key.startsWith('.');
        const domain = hostOnly ? row.host_key : row.host_key.slice(1);
        const path   = row.path;

        // console.log(convertChromiumTimestampToUnix(row.expires_utc))
        // console.log(new Date(convertChromiumTimestampToUnix(row.expires_utc) * 1000));
        const cookie = new tough.Cookie({
            key: row.name,
            value: row.value,
            domain: domain,
            path: row.path,
            hostOnly,
            creation: new Date(convertChromiumTimestampToUnix(row.creation_utc) * 1000),
            secure: row.is_secure === 1,
            httpOnly: row.is_httponly === 1,
            expires:  row.expires_utc ? new Date(convertChromiumTimestampToUnix(row.expires_utc) * 1000) : null,
            // sameSite: row.is_same_site
        });
        // console.log(cookie);

        const domainEntry = idx[domain] ?? (Object.create(null) as MemoryCookieStoreIndex[string])
        idx[domain] = domainEntry;

        const pathEntry =
            domainEntry[path] ??
            (Object.create(null) as MemoryCookieStoreIndex[string][string])
        domainEntry[path] = pathEntry;

        idx[domain][path][cookie.key] = cookie;

        // console.log(idx);
    }
    // return cookies;
}

export default class ChromeCookieJar extends tough.CookieJar {
    constructor(private profileOrPath?:string) {
        super();
    }

    public async initialize() {
        const idx = (this.store as MemoryCookieStore).idx;
        await injectChromeCookies(idx, this.profileOrPath);
    }
}