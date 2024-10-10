import got from 'got';
import ChromeCookieJar from '../src/index.js';

(async () => {
    const cj = new ChromeCookieJar();
    await cj.initialize();
    const res = await got('https://httpbin.org/cookies/set?name=robin', {
        cookieJar: cj,
    }).json();
    console.log(res);
})();