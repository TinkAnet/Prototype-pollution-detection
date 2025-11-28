import { injectable, inject, named, postConstruct, LazyServiceIdentifer } from 'inversify'
import express from 'express'
import * as http from 'http'
import * as yargs from 'yargs'
import { AddressInfo } from 'net'
import * as path from 'path'
import * as fs from 'fs-extra'
import { parse } from 'comment-json'
import { MaybePromise } from '../common/types'
import { CliContribution } from './cli'
import { ContributionProvider } from '../common/contribution-provider'
import { Deferred } from '../common/promise-util'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { HtmlRenderer } from './html-renderer'
const { createProxyMiddleware } = require('http-proxy-middleware')

const SENSITIVE_TERMS = ['key', 'password', 'secret', 'token', 'auth', 'credential'];

export interface ApplicationConfig {
    database: DatabaseConfig
    // tslint:disable-next-line: no-any
    [name: string]: any
}

export interface DatabaseConfig {
    port: number
    host: string
    user: string
    password: string
    schema: string
}

export const BackendApplicationContribution = Symbol('BackendApplicationContribution')
export interface BackendApplicationContribution {
    initialize?(): void
    configure?(app: express.Application): void
    onStart?(server: http.Server): MaybePromise<void>

    /**
     * Called when the backend application shuts down. Contributions must perform only synchronous operations.
     * Any kind of additional asynchronous work queued in the event loop will be ignored and abandoned.
     */
    onStop?(app?: express.Application): void
}

export const RawBackendApplicationContribution = Symbol('RawBackendApplicationContribution')
export interface RawBackendApplicationContribution {
    configureRaw?(app: express.Application): void
    onStopRaw?(app?: express.Application): void
}

const defaultPort = 3000
const defaultHost = 'localhost'
const defaultConfig = 'app-config.json'

const appProjectPath = 'app-project-path'

@injectable()
export class BackendApplicationCliContribution implements CliContribution {
    port: number
    hostname: string | undefined
    appConfig: string | undefined
    projectPath: string

    configure(conf: yargs.Argv): void {
        conf.option('port', {
            alias: 'p',
            description: 'The port the backend server listens on.',
            type: 'number',
            default: defaultPort,
        })
        conf.option('hostname', {
            alias: 'h',
            description: 'The allowed hostname for connections.',
            type: 'string',
            default: defaultHost,
        })
        conf.option('config', {
            alias: 'cfg',
            description: 'The json config for the application.',
            type: 'string',
            default: defaultConfig,
        })
        conf.option(appProjectPath, {
            description: 'Sets the application project directory',
            default: this.appProjectPath(),
        })
    }

    setArguments(args: yargs.Arguments): void {
        const portArg = args.port
        this.port = typeof portArg === 'number' ? portArg : defaultPort

        const hostArg = args.hostname
        this.hostname = typeof hostArg === 'string' ? hostArg : defaultHost

        const configArg = args.config
        this.appConfig = typeof configArg === 'string' ? configArg : defaultConfig

        const projectArg = args[appProjectPath]
        this.projectPath = typeof projectArg === 'string' ? projectArg : this.appProjectPath()
    }

    protected appProjectPath(): string {
        return process.cwd()
    }
}

function deepMerge(target: any, source: any): any {
    // Handle null/undefined cases
    if (!target) {
        return source;
    }
    if (!source) {
        return target;
    }

    // Create a new object to avoid modifying either input
    const result = { ...target };

    Object.keys(source).forEach(key => {
        if (source[key] instanceof Object && !Array.isArray(source[key])) {
            // If the key exists in target and is an object, recursively merge
            if (key in target && target[key] instanceof Object) {
                result[key] = deepMerge(target[key], source[key]);
            } else {
                // Otherwise just assign the source value
                result[key] = source[key];
            }
        } else {
            // For non-object values, simply override
            result[key] = source[key];
        }
    });

    return result;
}

function obfuscateConfig(config: any): any {
    if (!config || typeof config !== 'object') {
        return config;
    }

    const result: Partial<ApplicationConfig> = {};
    
    for (const [key, value] of Object.entries(config)) {
        if (typeof value === 'object') {
            result[key] = obfuscateConfig(value);
        } else if (
            typeof value === 'string' && 
            SENSITIVE_TERMS.some(term => key.toLowerCase().includes(term.toLowerCase()))
        ) {
            result[key] = value.length > 2 
                ? `${value[0]}${'*'.repeat(value.length - 2)}${value[value.length - 1]}`
                : value;
        } else {
            result[key] = value;
        }
    }
    
    return result;
}

@injectable()
export class ApplicationConfigProvider {
    public config: ApplicationConfig
    constructor(
        @inject(BackendApplicationCliContribution) protected readonly cliParams: BackendApplicationCliContribution
    ) {
        if (!this.cliParams.appConfig || !fs.pathExistsSync(this.cliParams.appConfig)) {
            throw new Error('Invalid App configuration')
        }

        const envConfig: Partial<ApplicationConfig> = {}
        // Read config file and override env vars with its contents
        const fileConfig = parse(fs.readFileSync(this.cliParams.appConfig).toString())
        
        this.config = deepMerge(fileConfig, envConfig)
        console.log("config: ", obfuscateConfig(this.config));
        return;
    }
}

@injectable()
export class BackendApplication {
    protected readonly app: express.Application = express()
    private staticFilesPath: string

    constructor(
        @inject(ContributionProvider)
        @named(BackendApplicationContribution)
        protected readonly contributionsProvider: ContributionProvider<BackendApplicationContribution>,
        @inject(ContributionProvider)
        @named(RawBackendApplicationContribution)
        protected readonly rawContributionsProvider: ContributionProvider<RawBackendApplicationContribution>,
        @inject(BackendApplicationCliContribution) protected readonly cliParams: BackendApplicationCliContribution,
        @inject(ApplicationConfigProvider) protected readonly appConfigProvider: ApplicationConfigProvider,
        @inject(new LazyServiceIdentifer(() => HtmlRenderer)) protected readonly htmlRenderer: HtmlRenderer
    ) {
        process.on('uncaughtException', (error) => {
            if (error) {
                if (!error.toString().includes('ERR_HTTP_HEADERS_SENT')) {
                    console.error('Uncaught Exception: ', error.toString())
                }
                if (error.stack && !error.stack.startsWith('Error [ERR_HTTP_HEADERS_SENT]')) {
                    console.error(error.stack)
                }
            }
        })
        // Handles normal process termination.
        process.on('exit', () => this.onStop())
        // Handles `Ctrl+C`.
        process.on('SIGINT', () => process.exit(0))
        // Handles `kill pid`.
        process.on('SIGTERM', () => process.exit(0))

        for (const contribution of this.contributionsProvider.getContributions()) {
            if (contribution.initialize) {
                try {
                    contribution.initialize()
                } catch (error) {
                    console.log('Could not initialize contribution', error)
                }
            }
        }
    }

    setStaticFilesPath(staticFilesPath: string): void {
        this.staticFilesPath = staticFilesPath
    }

    use(...handlers: express.Handler[]): void {
        const frontEndBasePath = this.appConfigProvider.config.frontEndBasePath;
        this.app.use(frontEndBasePath, ...handlers)
    }

    @postConstruct()
    protected init(): void {
        const basePath = this.appConfigProvider.config.basePath;
        for (const contribution of this.rawContributionsProvider.getContributions()) {
            if (contribution.configureRaw) {
                try {
                    contribution.configureRaw(this.app)
                } catch (error) {
                    console.error('Could not configure contribution', error)
                }
            }
        }
        const frontEndBasePath = this.appConfigProvider.config.frontEndBasePath;
        const webpackProxyEnabled = process.env.DEV_PROXY_WEBPACK === 'true'
        const webpackDevServerUrl = process.env.WEBPACK_DEV_SERVER_URL || 'http://localhost:3002'
        const rewriteDevServerPath = (incoming: string): string => {
            if (!frontEndBasePath || frontEndBasePath === '/' || frontEndBasePath === '//') {
                return incoming
            }
            if (!incoming.startsWith(frontEndBasePath)) {
                return incoming
            }
            const remainder = incoming.substring(frontEndBasePath.length)
            if (remainder.length === 0) {
                return '/'
            }
            return remainder.startsWith('/') ? remainder : `/${remainder}`
        }

        const webpackProxy = webpackProxyEnabled
            ? createProxyMiddleware({
                target: webpackDevServerUrl,
                changeOrigin: true,
                ws: true,
                logLevel: 'debug',
                pathRewrite: (path: string) => rewriteDevServerPath(path),
            })
            : undefined

        if (!webpackProxyEnabled) {
            this.app.get(`${frontEndBasePath}/*.js`, this.serveGzipped.bind(this, 'text/javascript'))
            this.app.get(`${frontEndBasePath}/*.js.map`, this.serveGzipped.bind(this, 'application/json'))
            this.app.get(`${frontEndBasePath}/*.css`, this.serveGzipped.bind(this, 'text/css'))
            this.app.get(`${frontEndBasePath}/*.wasm`, this.serveGzipped.bind(this, 'application/wasm'))
            this.app.get(`${frontEndBasePath}/*.gif`, this.serveGzipped.bind(this, 'image/gif'))
            this.app.get(`${frontEndBasePath}/*.png`, this.serveGzipped.bind(this, 'image/png'))
            this.app.get(`${frontEndBasePath}/*.svg`, this.serveGzipped.bind(this, 'image/svg+xml'))
        } else if (webpackProxy) {
            this.app.use((req, res, next) => {
                if (!req.path.startsWith(frontEndBasePath)) {
                    next()
                    return
                }
                const relativePath = req.path.substring(frontEndBasePath.length)
                const isRootRequest = relativePath.length === 0 || relativePath === '/' || relativePath === '//'
                const hasExtension = /\.[^/]+$/.test(relativePath)
                if (!hasExtension || isRootRequest) {
                    next()
                    return
                }
                webpackProxy(req, res, next)
            })
            this.app.use('/ws', webpackProxy)
        }

        const allowedOrigins: string[] = [];
        if (this.appConfigProvider.config.allowedOrigins) {
            allowedOrigins.push(...this.appConfigProvider.config.allowedOrigins)
        }
        const corsOptions = {
            origin: (origin: any, callback: any) => {
                if (allowedOrigins.includes(origin)) {
                    callback(undefined, origin)
                } else {
                    callback(undefined, true)
                }
            },
            methods: ['GET', 'POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            credentials: true
        }
        this.app.use(cors(corsOptions))
        this.app.use(cookieParser() as any)
        for (const contribution of this.contributionsProvider.getContributions()) {
            if (contribution.configure) {
                try {
                    contribution.configure(this.app)
                } catch (error) {
                    console.error('Could not configure contribution', error)
                }
            }
        }

        this.app.get(`${basePath}/health`, (req, res) => {
            res.json({ status: 'UP' })
        })
        if (!webpackProxyEnabled) {
            // SPA support
            const frontEndBasePathMap: Map<string, string> = new Map<string, string>();
            const bfs: string[] = []
            if (this.staticFilesPath) {
                fs.readdirSync(this.staticFilesPath).forEach((file) => {
                    bfs.push(path.join(this.staticFilesPath, file))
                })
                while (bfs.length > 0) {
                    const file = bfs.shift()
                    if (file) {
                        if (fs.statSync(file).isDirectory()) {
                            fs.readdirSync(file).forEach((subFile) => {
                                bfs.push(path.join(file, subFile))
                            })
                        } else {
                            const relativePath = path.relative(this.staticFilesPath, file).replace(/\\/g, '/')
                            if (relativePath.startsWith('..')) {
                                continue
                            }
                           frontEndBasePathMap.set(relativePath, file)
                        }
                    }
                }
            }

            this.app.get(`${frontEndBasePath}*`, async (req, res, next) => {
                if (req.path === frontEndBasePath || req.path === frontEndBasePath + '/') {
                    if (await this.tryRenderHtml(req, res)) {
                        return
                    }
                    next()
                    return
                }
                let file = req.path.substring(frontEndBasePath.length).split('?')[0]
                if (frontEndBasePathMap.has(file)) {
                    file = frontEndBasePathMap.get(file) || file
                    res.sendFile(file, { root: this.staticFilesPath })
                    return
                }
                let fileExists = false
                if (this.staticFilesPath) {
                    fileExists = fs.existsSync(path.join(this.staticFilesPath, file))
                    if (!fileExists) {
                        while (file.indexOf('/') >= 0) {
                            file = file.substring(file.lastIndexOf('/') + 1)
                            fileExists = fs.existsSync(path.join(this.staticFilesPath, file))
                            if (fileExists) {
                                break
                            }
                        }
                    }
                }
                if (!fileExists) {
                    if (await this.tryRenderHtml(req, res)) {
                        return
                    }
                    res.sendFile('index.html', { root: this.staticFilesPath })
                } else {
                    res.sendFile(file, { root: this.staticFilesPath })
                }
            });
        } else if (webpackProxy) {
            this.app.get(`${frontEndBasePath}*`, async (req, res, next) => {
                const relativePath = req.path.substring(frontEndBasePath.length)
                const hasExtension = /\.[^/]+$/.test(relativePath)
                if (!hasExtension || relativePath === '' || relativePath === '/' || relativePath === '//') {
                    if (await this.tryRenderHtml(req, res)) {
                        return
                    }
                }
                webpackProxy(req, res, next)
            })
        }
    }

    async start(aPort?: number, aHostname?: string): Promise<http.Server> {
        const hostname = aHostname !== undefined ? aHostname : this.cliParams.hostname
        const port = aPort !== undefined ? aPort : this.cliParams.port

        const deferred = new Deferred<http.Server>()
        const server: http.Server = http.createServer(this.app)

        server.on('error', (error) => {
            deferred.reject(error)
            /* The backend might run in a separate process,
             * so we defer `process.exit` to let time for logging in the parent process */
            setTimeout(process.exit, 0, 1)
        })

        server.listen(port, hostname, () => {
            const scheme = 'http'
            console.info(
                `Loops is listening on ${scheme}://${hostname || 'localhost'}:${
                    (server.address() as AddressInfo).port
                }.`
            )
            deferred.resolve(server)
        })

        /* Allow any number of websocket servers.  */
        server.setMaxListeners(0)

        for (const contrib of this.contributionsProvider.getContributions()) {
            if (contrib.onStart) {
                try {
                    await contrib.onStart(server)
                } catch (error) {
                    console.error('Could not start contribution', error)
                }
            }
        }
        return deferred.promise
    }

    protected async serveGzipped(
        contentType: string,
        req: express.Request,
        res: express.Response,
        next: express.NextFunction
    ): Promise<void> {
        const acceptedEncodings = req.acceptsEncodings()

        const gzUrl = `${req.url}.gz`
        const gzPath = path.join(this.cliParams.projectPath, 'public', gzUrl)
        if (acceptedEncodings.indexOf('gzip') === -1 || !(await fs.pathExists(gzPath))) {
            next()
            return
        }

        req.url = gzUrl

        res.set('Content-Encoding', 'gzip')
        res.set('Content-Type', contentType)

        next()
    }

    protected onStop(): void {
        for (const contrib of this.rawContributionsProvider.getContributions()) {
            if (contrib.onStopRaw) {
                try {
                    contrib.onStopRaw(this.app)
                } catch (error) {
                    console.error('Could not stop contribution', error)
                }
            }
        }
        for (const contrib of this.contributionsProvider.getContributions()) {
            if (contrib.onStop) {
                try {
                    contrib.onStop(this.app)
                } catch (error) {
                    console.error('Could not stop contribution', error)
                }
            }
        }
    }

    protected async tryRenderHtml(req: express.Request, res: express.Response): Promise<boolean> {
        try {
            const html = await this.htmlRenderer.render(req, this.appConfigProvider.config)
            if (html) {
                res.type('html').send(html)
                return true
            }
        } catch (error) {
            console.error('Failed to render SSR response', error)
        }
        return false
    }
}
