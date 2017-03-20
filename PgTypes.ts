import UUID from "hlandau.UUID";
import Int64 from "hlandau.Math/Int64";
import {IP, IPNet, MACAddr} from "hlandau.Net/Addr";
import {TextEncoder, TextDecoder} from "text-encoding";

const utf8 = new TextEncoder('utf-8');
const utf8d = new TextDecoder('utf-8');

export interface IFieldContext {
  getParam(name: string): string | undefined;
  readonly dataTypeOID: number;
}

export interface IFieldData extends IFieldContext {
  readonly data: Uint8Array;
  readonly dataTypeSize: number;
  readonly typeModifier: number;
  readonly formatCode: number;
}

export type DeserializerFunc = (data: IFieldData) => any;
export type SerializerFunc = (x: any, ctx: IFieldContext) => Uint8Array | undefined;

const _deserializers: {[oid: string]: DeserializerFunc} = {};
const _serializers: {[oid: string]: SerializerFunc} = {};

function _register<T>(oid: number | number[], m: {[oid: string]: T}, f: T) {
  const oids = (oid instanceof Array) ? oid : [oid];
  for (const oid of oids) {
    if (m[oid])
      throw new Error(`function already registered for OID ${oid}`);
    m[oid] = f;
  }
}

export function registerDeserializer(oid: number | number[], f: DeserializerFunc) {
  _register<DeserializerFunc>(oid, _deserializers, f);
}

export function registerSerializer(oid: number | number[], f: SerializerFunc) {
  _register<SerializerFunc>(oid, _serializers, f);
}

export function _getDeserializer(oid: number): DeserializerFunc | null {
  return _deserializers[oid] || null;
}

export function _getSerializer(oid: number): SerializerFunc | null {
  return _serializers[oid] || null;
}

enum StandardOID {
  bool        =   16,
  bytea       =   17,
  char        =   18,
  name        =   19,
  int8        =   20,
  int2        =   21,
  int4        =   23,
  oid         =   26,
  text        =   25,
  varchar     = 1043,
  json        =  142,
  jsonb       = 3802,
  float4      =  700,
  float8      =  701,
  macaddr     =  829,
  inet        =  869,
  cidr        =  650,
  uuid        = 2950,
  timestamp   = 1114,
  timestamptz = 1184,
  interval    = 1187,
  date        = 1082,
  time        = 1083,
  timetz      = 1266
}

function assertBinary(data: IFieldData) {
  if (data.formatCode !== 1)
    throw new Error(`field expected binary data, got format ${data.formatCode}`);
}

function assertLen(data: IFieldData, expectedLen: number) {
  assertBinary(data);
  if (data.data.length !== expectedLen)
    throw new Error(`field expected binary data of length ${expectedLen}, got ${data.data.length}`);
}

// All big endian.
/*function parseUint8(a: Uint8Array, offset: number): number {
  return a[offset];
}
function parseInt8(a: Uint8Array, offset: number): number {
  let v = parseUint8(a, offset);
  if (v >= 128)
    v -= 256;
  return v;
}*/
function parseUint16(a: Uint8Array, offset: number): number {
  return (a[offset+0] << 8) + a[offset+1];
}
function parseInt16(a: Uint8Array, offset: number): number {
  let v = parseUint16(a, offset);
  if (v >= 32768)
    v -= 65536;
  return v;
}
function parseUint32(a: Uint8Array, offset: number): number {
  return (a[offset+0] << 24) + (a[offset+1] << 16) + (a[offset+2] << 8) + a[offset+3];
}
function parseInt32(a: Uint8Array, offset: number): number {
  let v = parseUint32(a, offset);
  if (v >= 0x80000000)
    v -= 0x100000000;
  return v;
}

function parseInt64(a: Uint8Array, offset: number): Int64 {
  return Int64.make(parseUint32(a, offset+4), parseUint32(a, offset));
}

/* BOOL
 * ----
 */
registerDeserializer(StandardOID.bool, (data: IFieldData): any => {
  assertLen(data, 1);
  return !!data.data[0];
});

const bool0 = new Uint8Array(1);
const bool1 = new Uint8Array(1);
bool1[0] = 1;

registerSerializer(StandardOID.bool, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  return x ? bool1 : bool0;
});

/* INT2
 * ----
 */
registerDeserializer(StandardOID.int2, (data: IFieldData): any => {
  assertLen(data, 2);
  return parseInt16(data.data, 0);
});

registerSerializer(StandardOID.int2, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  const a = new Uint8Array(2);
  const av = new DataView(a.buffer);
  av.setInt16(0, x);
  return a;
});

/* INT4
 * ----
 */
registerDeserializer([StandardOID.int4, StandardOID.oid], (data: IFieldData): any => {
  assertLen(data, 4);
  return parseInt32(data.data, 0);
});

registerSerializer([StandardOID.int4, StandardOID.oid], (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  const a = new Uint8Array(4);
  const av = new DataView(a.buffer);
  av.setInt32(0, x);
  return a;
});

/* INT8
 * ----
 */
registerDeserializer(StandardOID.int8, (data: IFieldData): any => {
  assertLen(data, 8);
  return parseInt64(data.data, 0);
});

registerSerializer(StandardOID.int8, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  const x_ = Int64.ensure(x);

  const a = new Uint8Array(8);
  const av = new DataView(a.buffer);
  av.setInt32(0, x_.high32);
  av.setInt32(4, x_.low32);
  return a;
});

/* TEXT
 * ----
 */
registerDeserializer([StandardOID.text, StandardOID.name], (data: IFieldData): any => {
  assertBinary(data);
  return utf8d.decode(data.data);
});

registerSerializer([StandardOID.text, StandardOID.name], (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (typeof x !== 'string')
    throw new Error(`value for SQL TEXT must be a string`);

  return utf8.encode(x);
});

/* BYTEA
 * -----
 */
registerDeserializer(StandardOID.bytea, (data: IFieldData): any => {
  assertBinary(data);
  return data.data;
});

registerSerializer(StandardOID.bytea, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof Uint8Array))
    throw new Error(`value for SQL BYTEA must be a Uint8Array`);

  return x;
});

/* DATE
 * ----
 */
registerDeserializer(StandardOID.date, (data: IFieldData): any => {
  assertLen(data, 4);
  return j2date(parseInt32(data.data, 0));
});

registerSerializer(StandardOID.date, (x: any, ctx: IFieldContext): any => {
  if (!(x instanceof Date))
    throw new Error(`value for SQL DATE must be a Date`);
  if (x.getHours() !== 0 || x.getMinutes() !== 0 || x.getSeconds() !== 0 || x.getMilliseconds() !== 0)
    throw new Error(`value for SQL DATE must be a Date at midnight`);

  const a = new Uint8Array(4);
  const av = new DataView(a.buffer);
  av.setInt32(0, date2j(x));
  return a;
});

function timePad(x: number): string {
  const x_ = x.toString();
  if (x_.length === 2)
    return x_;
  return '0' + x_;
}

export class Time {
  private __us: Int64; // Time since start of day in μs

  constructor(us: Int64) {
    this.__us = us;
    Object.freeze(this);
  }

  get us(): Int64 { return this.__us; }

  get hour(): number {
    return Int64.div(this.__us, Int64.make(1000000*60*60)).toNumber();
  }

  get minute(): number {
    return Int64.div(this.__us, Int64.make(1000000*60)).toNumber() % 60;
  }

  get second(): number {
    return Int64.div(this.__us, Int64.make(1000000)).toNumber() % 60;
  }

  toTimeString(): string {
    return `${timePad(this.hour)}:${timePad(this.minute)}:${timePad(this.second)}`;
  }

  toString(): string {
    return `Time(${this.toTimeString()})`;
  }
}

export class TimeTZ {
  private __time: Time;
  private __tzOffset: number; // Timezone offset in seconds from UTC.

  constructor(time: Time, tzOffset: number=0) {
    this.__time = time;
    this.__tzOffset = tzOffset;
    Object.freeze(this);
  }

  get time(): Time { return this.__time; }
  get tzOffset(): number { return this.__tzOffset; }

  toString(): string {
    const o = this.tzOffset;
    const o_ = Math.abs(o);
    const h = timePad((o_/(60*60))|0);
    const m = timePad(((o_%(60*60))/60)|0);
    const s = timePad(o_%60);
    return `TimeTZ(${this.time}${o < 0 ? '-' : '+'}${h}:${m}:${s})`;
  }
}

/* TIME
 * ----
 */
registerDeserializer(StandardOID.time, (data: IFieldData): any => {
  assertLen(data, 8);
  return new Time(parseInt64(data.data, 0));
});
registerSerializer(StandardOID.time, (x: any, ctx: IFieldContext): any => {
  if (!(x instanceof Time))
    throw new Error(`value for SQL TIME must be a Time object`);

  const a = new Uint8Array(8);
  const av = new DataView(a.buffer);
  av.setInt32(0, x.us.high32);
  av.setInt32(4, x.us.low32);
  return a;
});

/* TIMETZ
 * ------
 */
registerDeserializer(StandardOID.timetz, (data: IFieldData): any => {
  assertLen(data, 12);
  const us = parseInt64(data.data, 0);
  const tzs = parseInt32(data.data, 8); // timezone offset in seconds
  return [us, tzs]; // TODO
});
registerSerializer(StandardOID.timetz, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof TimeTZ))
    throw new Error(`value for SQL TIMETZ must be a TimeTZ object`);

  const a = new Uint8Array(12);
  const av = new DataView(a.buffer);
  av.setInt32(0, x.time.us.high32);
  av.setInt32(4, x.time.us.low32);
  av.setInt32(8, x.tzOffset);
  return a;
});

/* TIMESTAMP
 * ---------
 */
const i64_1000 = Int64.make(1000);
registerDeserializer([StandardOID.timestamp, StandardOID.timestamptz], (data: IFieldData): any => {
  assertLen(data, 8);

  const v_us = parseInt64(data.data, 0); // us since 2000-01-01 00:00:00.000000 UTC.
  const v_ms = Int64.div(v_us, i64_1000).toNumber();

  const unix_ms = v_ms + 10957*24*60*60*1000;
  return new Date(unix_ms);
});

registerSerializer([StandardOID.timestamp, StandardOID.timestamptz], (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof Date))
    throw new Error(`value for SQL TIMESTAMP/TIMESTAMPTZ field must be a Date object`);

  const unix_ms = x.getTime();
  const pg_ms   = unix_ms - 10957*24*60*60*1000;
  const pg_us   = Int64.mul(Int64.make(pg_ms), i64_1000);

  const a = new Uint8Array(8);
  const av = new DataView(a.buffer);
  av.setUint32(0, pg_us.high32);
  av.setUint32(4, pg_us.low32);
  return a;
});

export class Interval {
  private __us: Int64; // μs

  constructor(us: Int64) {
    this.__us = us;
    Object.freeze(this);
  }

  get us(): Int64 { return this.__us; }

  toString(): string {
    return `Interval(${this.us})`;
  }
}

/* INTERVAL
 * --------
 */
const i64_us = Int64.make(60*60*24*1000000);
registerDeserializer(StandardOID.interval, (data: IFieldData): any => {
  assertLen(data, 16);

  const us  = parseInt64(data.data, 0);
  const mon = parseInt32(data.data, 8);
  const day = parseInt32(data.data, 12);

  let v = Int64.add(us, Int64.mul(Int64.make(day   ), i64_us));
      v = Int64.add(v,  Int64.mul(Int64.make(mon*31), i64_us))
  return new Interval(v);
});

registerSerializer(StandardOID.interval, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof Interval))
    throw new Error(`value for SQL INTERVAL field must be an Interval object`);

  const a = new Uint8Array(16);
  const av = new DataView(a.buffer);
  av.setUint32(0, x.us.high32);
  av.setUint32(4, x.us.low32);
  av.setUint32(8, 0);
  av.setUint32(12, 0);
  return a;
});


/* UUID
 * ----
 */
registerDeserializer(StandardOID.uuid, (data: IFieldData): any => {
  assertLen(data, 16);
  return new UUID(data.data);
});
registerSerializer(StandardOID.uuid, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof UUID))
    throw new Error(`value for SQL UUID field must be a UUID object`);

  return x.bytes;
});

/* INET
 * ----
 */
registerDeserializer(StandardOID.inet, (data: IFieldData): any => {
  assertBinary(data);
  if (data.data.length !== 8 && data.data.length !== 20)
    throw new Error(`inet expected binary data of length 8 or 20`);

  //  1  ui  Address Family
  //  1  ui  Prefix Length
  //  1  ui  Is CIDR? (0 or 1)
  //  1  ui  Address Length (4 or 16)
  //  ...    Binary Data
  // IPv4: 2
  // IPv6: 3
  switch (data.data[0]) {
  case 2: // IPv4
    if (data.data[3] !== 4)
      throw new Error(`unexpected binary data length for IPv4 inet field`);
    return new IPNet(new IP(data.data.subarray(4)), data.data[1]);
  case 3: // IPv6
    if (data.data[3] !== 16)
      throw new Error(`unexpected binary data length for IPv6 inet field`);
    return new IPNet(new IP(data.data.subarray(4)), data.data[1]);
  default:
    throw new Error(`inet received unexpected address family ${data.data[0]}`);
  }
});
registerSerializer(StandardOID.inet, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (x instanceof IP)
    x = new IPNet(x);

  if (!(x instanceof IPNet))
    throw new Error(`value for SQL INET field must be an IPNet object`);

  const L  = (x.isV4 ? 4 : 16);
  const Lb = L + 4;

  const a = new Uint8Array(Lb);
  a[0] = x.isV4 ? 2 : 3;
  a[1] = x.prefixLength;
  a[2] = (x.prefixLength < (x.isV4 ? 32 : 128)) ? 1 : 0;
  a[3] = L;

  const ib = x.ip.bytes;
  for (let i=0; i<ib.length; ++i)
    a[4+i] = ib[i];

  return a;
});

/* MACADDR
 * -------
 */
registerDeserializer(StandardOID.macaddr, (data: IFieldData): any => {
  assertLen(data, 6);
  return new MACAddr(data.data);
});
registerSerializer(StandardOID.macaddr, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  if (!(x instanceof MACAddr))
    throw new Error(`value for SQL MACADDR field must be a MACAddr object`);

  return x.bytes;
});

/* JSON
 * ----
 */
registerDeserializer(StandardOID.json, (data: IFieldData): any => {
  assertBinary(data);

  return JSON.parse(utf8d.decode(data.data));
});
registerSerializer(StandardOID.json, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  return utf8.encode(JSON.stringify(x));
});

/* JSONB
 * -----
 */
registerDeserializer(StandardOID.jsonb, (data: IFieldData): any => {
  assertBinary(data);
  if (data.data.length < 1)
    throw new Error(`jsonb expected binary data of length of at least 1`);

  const v = data.data[0];
  if (v !== 1)
    throw new Error(`unexpected jsonb version: ${v}`);

  return JSON.parse(utf8d.decode(data.data.subarray(1)));
});

registerSerializer(StandardOID.jsonb, (x: any, ctx: IFieldContext): Uint8Array | undefined => {
  const d = utf8.encode(JSON.stringify(x));
  const a = new Uint8Array(d.length+1);
  a[0] = 1;
  for (let i=0; i<d.length; ++i)
    a[i+1] = d[i];
  return a;
});

function date2j(date: Date): number {
  let y = date.getFullYear();
  let m = date.getMonth();
  const d = date.getDay();

  if (m > 2) {
    m += 1;
    y += 4800;
  } else {
    m += 13;
    y += 4799;
  }

  const century = (y/100)|0;
  let julian = y*365 - 32167;
  julian += ((y/4)|0) - century + (century/4)|0;
  julian += (((7834*m)/256)|0) + d;

  return julian;
}

function j2date(jd: number): Date {
  let julian: number;
  let quad: number;
  let extra: number;
  let y: number;

  julian  = jd;
  julian += 32044;
  quad    = julian / 146097;
  extra   = (julian - quad * 146097) * 4 + 3;
  julian += 60 + quad * 3 + extra / 146097;
  quad    = julian / 1461;
  julian -= quad * 1461;
  y       = julian * 4 / 1461;
  julian  = ((y !== 0) ? ((julian + 305) % 365) : ((julian + 306) % 366)) + 123;
  y      += quad*4;
  const year  = y - 4800;
  quad    = julian * 2141 / 65536;
  const day   = julian - 7834 * quad / 256;
  const month = (quad + 10) % 12 + 1;

  return new Date(year, month-1, day);
}
