import puppeteer, {Browser} from 'puppeteer';
import {Collection, Db, Document, MongoClient} from 'mongodb';
import {parseString} from 'xml2js';
import * as util from "util";
import asyncPool from 'tiny-async-pool';
import {Presets, SingleBar} from 'cli-progress';

const parseStringPromise = util.promisify(parseString);

// valuable selectors:

// div.feed__item

// div.content-title
// div.l-island-a
//     time.time
//     span.comments_counter__count__value
//     span.like-button__count

//     div.post-counters__item
//     span.post-counters__value
//     span.post-counters__label

//     a.content-link

class Downloader {
    private progressBar: SingleBar;

    constructor(private browser: Browser, private db: Db) {
        this.progressBar = new SingleBar({
            format: 'progress [{bar}] {percentage}% | ETA: {eta}s  | {speed} | {duration_formatted} | {value}/{total}'
        }, Presets.shades_classic);
    }

    async downloadPost(record: Record<string, any>): Promise<void> {
        try {
            const {_id, url} = record;
            const page = await this.browser.newPage();
            await page.setRequestInterception(true);
            page.on('request', (req) => {
                if (req.resourceType() === 'stylesheet' || req.resourceType() === 'font' || req.resourceType() === 'image') {
                    req.abort();
                } else {
                    req.continue();
                }
            });
            await page.goto(url, {waitUntil: 'domcontentloaded'});
            const post = await page.evaluate(() => {
                const title = document.querySelector('h1.content-title')?.textContent;
                const counters = document.querySelector('div.post-counters');
                if (!counters) {
                    return null;
                }
                const views = counters.getAttribute('data-views');
                const hits = counters.getAttribute('data-hits');
                const articleInfoDiv = document.querySelector('div.l-hidden.entry_data');
                if (!articleInfoDiv) {
                    return null;
                }
                const articleInfo = JSON.parse(articleInfoDiv.getAttribute('data-article-info'));
                const contentDiv = document.querySelector('div.content.content--full');
                if (!contentDiv) {
                    return null;
                }
                const content = contentDiv.innerHTML;
                return {
                    title: (title || '').trim(),
                    content: (content || '').trim(),
                    ...articleInfo,
                    views: parseInt(views),
                    hits: parseInt(hits),
                    createdAt: new Date(),
                };
            });
            if (!post) {
                await page.close();
                return;
            }
            await Promise.all([
                page.close(),
                this.db.collection('vc_urls').updateOne({_id}, {$set: {downloadedAt: new Date()}}),
                this.db.collection('vc_posts').insertOne({
                    ...post,
                    url: url,
                    createdAt: new Date(),
                })
            ]);
        } catch (e) {
            console.error(e);
        }
    }

    async downloadUrls() {
        const records = await this.db.collection('vc_urls').find({
            downloadedAt: {$exists: false},
        }).sort({_id: -1}).toArray();
        const start = new Date();
        this.progressBar.start(records.length, 0, {
            speed: "N/A"
        });
        let count = 0;
        for await (const _ of asyncPool(12, records, this.downloadPost.bind(this))) {
            count++;
            this.progressBar.update(count, {
                speed: `${(count / (new Date().getTime() - start.getTime()) * 1000).toFixed(2)} urls/s`
            });
        }
    }
}

async function _downloadSiteMap(collection: Collection<Document>, sitemapUrl: string) {
    const response = await fetch(sitemapUrl);
    const text = await response.text();
    const result: any = await parseStringPromise(text);
    const urls = result.urlset.url.map((url: any) => url.loc[0]);
    try {
        await collection.insertMany(urls.map((url: string) => ({
            url,
            createdAt: new Date(),
        })));
    } catch (e) {
        if (e.code !== 11000) {
            throw e;
        }
    }
}

async function downloadSiteMap(browser: Browser, collection: Collection<Document>, sitemapUrl: string) {
    const page = await browser.newPage();
    await page.goto(sitemapUrl);
    await new Promise(resolve => setTimeout(resolve, 1000));
    let urls = await page.evaluate(() => {
        const urls = [];
        const links = document.querySelectorAll('loc');
        for (const link of links) {
            urls.push(link.innerHTML);
        }
        return urls;
    });
    urls = urls.filter((url: string) => url.includes('year'));
    for (const url of urls) {
        await _downloadSiteMap(collection, url);
    }
    await page.close();
}

async function main() {
    const mongoClient = new MongoClient('mongodb://localhost:27017/amadeus', {});
    await mongoClient.connect();
    const db = mongoClient.db('amadeus');
    await db.collection('vc_urls').createIndex({url: 1}, {unique: true});
    await db.collection('vc_posts').createIndex({url: 1}, {unique: true});

    const browser = await puppeteer.launch({headless: true});

    // await downloadSiteMap(browser, db.collection('vc_urls'), 'https://vc.ru/sitemap.xml');

    const downloader = new Downloader(browser, db);
    await downloader.downloadUrls();
    await browser.close();
}

main().then(() => {
    process.exit(0);
}).catch((err) => {
    console.error(err);
});