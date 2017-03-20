import * as NetLoc from "hlandau.Net/NetLoc";
import * as url from "url";

// Specifies the TLS policy to use when connecting.
export enum TLSMode {
  Default,     // Equivalent to Prefer.

  Never,       // Never use TLS.
  Allow,       // Allow TLS, but prefer not to use it.
  Prefer,      // Try to use TLS, but don't require it. Default.
  Require,     // Require the use of TLS, but don't validate certificates.
  VerifyFull,  // Require TLS and fully validate certificates.
}

function parseTLSMode(s: string): TLSMode {
  switch (s) {
  case '':
    return TLSMode.Default;
  case 'never':
    return TLSMode.Never;
  case 'allow':
    return TLSMode.Allow;
  case 'prefer':
    return TLSMode.Prefer;
  case 'require':
    return TLSMode.Require;
  case 'verify-full':
    return TLSMode.VerifyFull;
  default:
    throw new Error(`unrecognised TLS mode: "${s}"`);
  }
}

// Specifies the parameters used to construct a ConnectionSpec.
export interface ConnectionSpecArgs {
  dbName?: string;   // Database name.
  hostName?: string; // Hostname (e.g. "localhost", "localhost:1234", "[IPv6]:port").
  userName?: string; // Username.
  password?: string; // Password.
  tlsMode?: TLSMode; // TLS mode.
}

export type GetEnvFunc = (envName: string) => string | undefined;

// These options control connection specification resolution for ConnectionSpec
// construction functions which take accept potentially incomplete connection
// specifications.
export interface ConnectionSpecResolveOptions {
  // If false, environment variable fallback is inhibited, as though no
  // environment variables are set. If true or absent (undefined), looks up
  // environment variables to try and provide default values for connection
  // specification arguments which were not explicitly specified.
  //
  // If set to a function taking a single string as an argument, called with
  // the environment variable name whenever an environment variable lookup is
  // attempted, instead of doing the lookup against the OS environment. The
  // return value must be a (potentially empty) string, or undefined if the
  // environment variable is not set at all.
  env?: boolean | GetEnvFunc;
}

// A ConnectionSpec is an immutable object which represents a complete set of
// PostgreSQL database connection parameters. A ConnectionSpec always
// represents a set of parameters after any inheritance or built-in values are
// applied, and therefore never needs to have any further fallbacks applied to
// its values.
//
// PostgreSQL connection objects connect to databases using a ConnectionSpec
// and do not apply any environment variable or built-in value fallback by
// themselves. If the values specified directly in the ConnectionSpec are not
// by themselves adequate to connect to a database, the connection fails.
//
// Environment variable and built-in value fallback is performed when
// constructing a ConnectionSpec, and only at that time.
//
// Most users will want to use ConnectionSpec.fromString to construct a
// ConnectionSpec from a PostgreSQL URL or DSN.
const symPrivate = Symbol();
export class ConnectionSpec {
  private __args: ConnectionSpecArgs;

  private constructor(sym: Symbol, args: ConnectionSpecArgs) {
    if (sym !== symPrivate)
      throw new Error(`do not invoke new ConnectionSpec() directly; use ConnectionSpec.fromArgs or similar`);

    this.__args = Object.freeze(args);
    Object.freeze(this);

    if (!isnzString(this.__args.hostName))
      throw new Error(`ConnectionSpec must have hostname`);
    if (!isnzString(this.__args.userName))
      throw new Error(`ConnectionSpec must have username`);
    if (!isnzString(this.__args.dbName))
      throw new Error(`ConnectionSpec must have database name`);
  }

  // Construct a ConnectionSpec from a complete set of arguments. No
  // environment variable or built-in value fallback is performed, and an error
  // is thrown if any arguments are missing or invalid.
  //
  // Most users will want ConnectionSpec.fromArgs or ConnectionSpec.fromString.
  static fromCompleteArgs(args: ConnectionSpecArgs): ConnectionSpec {
    return new ConnectionSpec(symPrivate, Object.assign({}, args));
  }

  private static __fromArgs(args: ConnectionSpecArgs, options: ConnectionSpecResolveOptions, srcKeyName: string): ConnectionSpec {
    args = Object.assign({}, args);

    for (const af of argsFields)
      _fieldInherit(args, af, options, srcKeyName);

    return new ConnectionSpec(symPrivate, args);
  }

  // Construct a ConnectionSpec from a (potentially incomplete) set of arguments.
  //
  // Environment variable (and, failing that, built-in value) fallback is used
  // to complete the set of arguments.
  static fromArgs(args: ConnectionSpecArgs, options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    return ConnectionSpec.__fromArgs(args, options, 'argsName');
  }

  // Construct a ConnectionSpec from a string which is either a PostgreSQL URL
  // (`postgresql://`) or a PostgreSQL-format DSN. The format is detected
  // automatically, and either format can be specified. If the string cannot
  // be parsed as either format, an error is thrown.
  //
  // Environment variable (and failing that, built-in value) fallback is used
  // if the information provided via the string is incomplete.
  //
  // The environment variables and built-in defaults used are shown below.
  //
  // The following table shows the supported DSN parameters:
  //
  //                       Inheritable by URL from environment variables
  //   Spec. Name.   Param.    v Env.        Default.
  //   hostName ]    host        PGHOST      "localhost"
  //   hostName ]    port      * PGPORT      5432
  //   userName      user      * PGUSER      (OS username for executing process)
  //   password      password  * PGPASSWORD  (none)
  //   tlsMode       sslmode   * PGSSLMODE   "prefer"
  //   dbName        dbname      PGDATABASE  "postgres"
  //
  // Not all DSN parameters supported by libpq are supported by this library;
  // only the ones described above are supported.
  static fromString(str: string, options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    if (str.indexOf('postgresql:') === 0)
      return ConnectionSpec.fromURL(str, options);

    return ConnectionSpec.fromDSN(str, options);
  }

  // Construct a ConnectionSpec from a string which is a libpq-style DSN,
  // using environment variables or built-in defaults as fallbacks where
  // appropriate.
  //
  // Note that an empty DSN string is a valid DSN, and causes all values to
  // be taken from environment variables or built-in defaults.
  //
  // This is like fromString, but throws if an URL is passed.
  static fromDSN(str: string, options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    if (!str.match(/^([a-zA-Z0-9_]+=[^ ]*(\s+|$)){0,}(\s*password=.*)?$/))
      throw new Error(`invalid PostgreSQL connection DSN: "${str}"`);

    const params: {[k: string]: string} = {};
    str.replace(/((password)=(.*$)|([a-zA-Z0-9_]+)=([^ ]*))/g, (m: string, ...ms: any[]): string => {
      if (ms[1] !== undefined)
        params[ms[1]] = ms[2];
      else
        params[ms[3]] = ms[4];
      return m;
    });

    return ConnectionSpec.__fromArgs(params, options, 'dsnName');
  }

  // Construct a ConnectionSpec from a string which is a PostgreSQL URL
  // (`postgresql://`). Since many fields in URLs must always be specified,
  // the only environment variable and built-in default fallbacks applied are
  // for username, password and port, or additional supported parameters which
  // may be passed by query string, such as the TLS mode. An URL-based
  // connection string is always considered to fully specify its hostname and
  // database name.
  //
  // This is like fromString, but throws if a DSN is passed.
  static fromURL(str: string, options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    const u = new (url as any).URL(str);
    if (u.protocol !== 'postgresql:')
      throw new Error(`unknown URL scheme: expected "postgresql", got "${u.protocol}"`);

    const dbName = u.pathname.length > 0 ? u.pathname.substr(1) : undefined;

    return ConnectionSpec.fromArgs({
      dbName:   dbName,
      hostName: u.host,
      userName: u.username || undefined,
      password: u.password || undefined,
      tlsMode:  u.searchParams.get('sslmode') || undefined,
    }, options);
  }

  // Construct a ConnectionSpec from environment variables and built-in
  // defaults only.
  //
  // This is equivalent to calling fromDSN('').
  static fromEnv(options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    return ConnectionSpec.fromString('', options);
  }

  // Ensure that x is a ConnectionSpec. If it is not, automatically create a
  // ConnectionSpec from it if it is a string or object.
  static ensure(x: ConnectionSpec | ConnectionSpecArgs | string, options: ConnectionSpecResolveOptions={}): ConnectionSpec {
    if (x instanceof ConnectionSpec)
      return x;
    if (x instanceof String)
      return ConnectionSpec.fromString(x, options);
    if (typeof x === 'object')
      return ConnectionSpec.fromArgs(x, options);

    throw new Error(`ConnectionSpec requires ConnectionSpec, string or object`);
  }


  // Convert the ConnectionSpec to a complete ConnectionSpecArgs object.
  toArgs(): ConnectionSpecArgs {
    return this.__args;
  }
  get args(): ConnectionSpecArgs { return this.toArgs(); }

  get hostName(): string { return this.args.hostName || ''; }
  get userName(): string { return this.args.userName || ''; }
  get password(): string { return this.args.password || ''; }
  get dbName(): string { return this.args.dbName || ''; }
  get tlsMode(): TLSMode { return this.args.tlsMode || TLSMode.Prefer; }

  /*// Convert the ConnectionSpec to a comprehensive DSN string.
  //
  // Note that since this includes any arguments incorporated by virtue of
  // environment variable or built-in value fallback, it may contain more
  // arguments than were originally used to construct the ConnectionSpec.
  toDSN(): string {
    return '';
  }
  get dsn(): string { return this.toDSN(); }

  // Convert the ConnectionSpec to a comprehensive `postgresql://` URL.
  //
  // Note that since this includes any arguments incorporated by virtue of
  // environment variable or built-in value fallback, it may contain more
  // arguments than were originally used to construct the ConnectionSpec.
  toURL(): string {
    return '';
  }
  get url(): string { return this.toURL(); }

  // Convert the ConnectionSpec to a set of equivalent environment variables,
  // represented as key-value pairs in an object.
  toEnv(): {[envName: string]: string} {
    return {};
  }
  get env(): {[envName: string]: string} { return this.toEnv(); }*/

  // String representation of ConnectionSpec for debug purposes.
  toString(): string {
    return `[SQLAPI-Pg.ConnectionSpec: "${this.args}"]`;
  }
}


/* Parsing Utilities */
interface ArgsFieldSpec {
  dsnName: string;
  argsName: string;
  envName: string;
  defaultValue: any;

  setter?(args: ConnectionSpecArgs, v: any): void;
  isSet?(args: ConnectionSpecArgs): boolean;
}

const argsFields: ArgsFieldSpec[] = [
  {dsnName: 'host', argsName: 'hostName', envName: 'PGHOST',     defaultValue: 'localhost',
    setter(args: ConnectionSpecArgs, v: any) {
      let [h, p] = NetLoc.split(args.hostName || 'x:');
      h = v;
      args.hostName = NetLoc.join(h, p);
    },
    isSet(args: ConnectionSpecArgs): boolean {
      return !!(args.hostName && NetLoc.split(args.hostName)[0]);
    },
  },
  {dsnName: 'port',     argsName: '__port',   envName: 'PGPORT',     defaultValue: 5432,
    setter(args: ConnectionSpecArgs, v: any) {
      let [h, p] = NetLoc.split(args.hostName || '');
      p = v;
      args.hostName = NetLoc.join(h, p);
    },
    isSet(args: ConnectionSpecArgs): boolean {
      return !!(args.hostName && NetLoc.split(args.hostName)[1]);
    },
  },
  {dsnName: 'sslmode',  argsName: 'tlsMode',  envName: 'PGSSLMODE',  defaultValue: 'prefer',
    setter(args: ConnectionSpecArgs, v: any) {
      if (v !== undefined)
        args.tlsMode = parseTLSMode(v);
    },
  },
  {dsnName: 'user',     argsName: 'userName', envName: 'PGUSER',     defaultValue: () => require('os').userInfo().username},
  {dsnName: 'password', argsName: 'password', envName: 'PGPASSWORD', defaultValue: ''},
  {dsnName: 'dbname',   argsName: 'dbName',   envName: 'PGDATABASE', defaultValue: 'postgres'},
];

function _getFromEnv(options: ConnectionSpecResolveOptions, envName: string): string | undefined {
  if (options.env === false)
    return undefined;
  if (options.env === true || options.env === undefined)
    return process.env[envName];
  return options.env(envName);
}

function _fieldSet(args: ConnectionSpecArgs, af: ArgsFieldSpec, v: any) {
  if (af.setter)
    af.setter(args, v);
  else
    (args as any)[af.argsName] = v;
}

function _fieldIsSet(args: ConnectionSpecArgs, af: ArgsFieldSpec): boolean {
  if (af.isSet)
    return af.isSet(args);
  else
    return (args as any)[af.argsName] !== undefined;
}

function _fieldInherit(args: ConnectionSpecArgs, af: ArgsFieldSpec, options: ConnectionSpecResolveOptions, srcKeyName: string) {
  const args_ = args as any;
  const af_ = af as any;

  const v = args_[af_[srcKeyName]];
  if (v !== undefined) {
    delete(args_[af_[srcKeyName]]);
    _fieldSet(args, af, v);
  }

  if (_fieldIsSet(args, af))
    return;

  if (af.envName)
    _fieldSet(args, af, _getFromEnv(options, af.envName));
  if (_fieldIsSet(args, af))
    return;

  let dv = af.defaultValue;
  if (dv instanceof Function)
    dv = dv();
  _fieldSet(args, af, dv);
}

function isnzString(s: string | undefined): boolean {
  return (typeof s === 'string' && s.length > 0);
}
