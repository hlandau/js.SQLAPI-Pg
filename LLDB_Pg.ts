import {ILLDBDriver, ILLDBConnection, ILLDBConnectionTx, ILLDBConnectionTxOptions, ILLDBResult, ILLDBRows, registerDriver} from "hlandau.SQLAPI/LLDB";
import {ConnectionSpec, ConnectionSpecArgs} from "hlandau.SQLAPI-Pg/ConnectionSpec";
import {IConn, IDialer, dialer} from "hlandau.Net/Dial";
import {IContext, background} from "hlandau.Context";
import {TextEncoder, TextDecoder} from "text-encoding";
import {_getDeserializer, _getSerializer, IFieldData} from "hlandau.SQLAPI-Pg/PgTypes";
import * as crypto from "crypto";

(Symbol as any).asyncIterator = Symbol.asyncIterator || Symbol.for('Symbol.asyncIterator');

const errorResponseFieldMapping: {[k: string]: string} = {'V': 'severity', 'C': 'sqlstate', 'M': 'message', 'D': 'detail', 'H': 'hint', 'P': 'position', 'p': 'internalPosition', 'q': 'internalQuery', 'W': 'where', 's': 'schemaName', 't': 'tableName', 'c': 'columnName', 'd': 'dataTypeName', 'n': 'constraintName', 'F': 'filename', 'L': 'lineNo', 'R': 'routine'};

const utf8 = new TextEncoder('utf-8');
const utf8d = new TextDecoder('utf-8');

const allBinary = [1];

function readString(dv: DataView, pos: number): [string, number] {
  for (let i=pos, len=dv.buffer.byteLength; i < len; ++i)
    if (dv.getUint8(i) === 0)
      return [utf8d.decode(new Uint8Array(dv.buffer, dv.byteOffset+pos, i-pos)), i+1];

  throw new Error(`unterminated string in buffer`);
}

function copyBytes(dv: DataView, offset: number, a: Uint8Array) {
  for (let i=0, len=a.length; i<len; ++i)
    dv.setUint8(offset+i, a[i]);
}

function copyBytesZ(dv: DataView, offset: number, a: Uint8Array) {
  copyBytes(dv, offset, a);
  dv.setUint8(offset+a.length, 0);
}

function getMessageType(d: Uint8Array): number {
  return d[0];
}

enum MessageType {
  AuthenticationRequest  = 0x52, // < 'R'
  BackendKeyData         = 0x4B, // < 'K'
  Bind                   = 0x42, // > 'B'
  BindComplete           = 0x32, // < '2'
  Close                  = 0x43, // > 'C'
  CloseComplete          = 0x33, // < '3'
  CommandComplete        = 0x43, // < 'C'
  CopyData               = 0x64, // = 'd'
  CopyDone               = 0x63, // = 'c'
  CopyFail               = 0x66, // = 'f'
  CopyInResponse         = 0x47, // < 'G'
  CopyOutResponse        = 0x48, // < 'H'
  CopyBothResponse       = 0x57, // < 'W'
  DataRow                = 0x44, // < 'D'
  Describe               = 0x44, // > 'D'
  EmptyQueryResponse     = 0x49, // < 'I'
  ErrorResponse          = 0x45, // < 'E'
  Execute                = 0x45, // > 'E'
  Flush                  = 0x48, // > 'H'
  NoData                 = 0x6E, // < 'n'
  NoticeResponse         = 0x4E, // < 'N'
  NotificationResponse   = 0x41, // < 'A'
  ParameterDescription   = 0x74, // < 't'
  ParameterStatus        = 0x53, // < 'S'
  Parse                  = 0x50, // > 'P'
  ParseComplete          = 0x31, // < '1'
  Password               = 0x70, // > 'p'
  PortalSuspended        = 0x73, // < 's'
  Query                  = 0x51, // > 'Q'
  ReadyForQuery          = 0x5A, // > 'Z'
  RowDescription         = 0x54, // < 'T'
  Sync                   = 0x53, // > 'S'
  Terminate              = 0x58, // > 'X'
}

export interface Notice {
  severity: string;
  sqlstate?: string;
  message: string;
  filename?: string;
  lineNo?: string;
  routine?: string;

  detail?: string;
  hint?: string;
  position?: string;
  internalPosition?: string;
  internalQuery?: string;
  where?: string;
  schemaName?: string;
  tableName?: string;
  columnName?: string;
  dataTypeName?: string;
  constraintName?: string;
}

const __formatDefaults: {[k:string]: number} = {severity:1,sqlstate:1,message:1,filename:1,lineNo:1,routine:1,S:1};
function formatResponse(mr: Notice): string {
  let s = `${mr.severity}: ${mr.sqlstate}: ${mr.message}`;
  if (mr.filename || mr.lineNo !== undefined)
    s += ` (${mr.filename || ''}:${mr.lineNo}${mr.routine ? ':'+mr.routine : ''})`;
  for (const k in mr) {
    if (__formatDefaults[k])
      continue;
    s += `\n    ${k}: ${(mr as any)[k]}`;
  }
  return s;
}

interface Notification {
  readonly pid: number;
  readonly channelName: string;
  readonly channelData: string;
}

interface AuthenticationRequest {
  type: string;
  salt?: Uint8Array;
}

interface MsgFieldDescription {
  index: number;
  fieldName: string;
  tableOID: number;
  columnAttributeNo: number;
  dataTypeOID: number;
  dataTypeSize: number;
  typeModifier: number;
  formatCode: number;
}

export class PgError extends Error {
  constructor(mr: Notice) {
    super(`Pg server error:\n  ${formatResponse(mr)}`);
  }
}

export interface IPgConnectionArgs {
  connectionSpec?: ConnectionSpec | ConnectionSpecArgs | string;
  dialer?: IDialer | null;

  // If set, called when a notification is received. Otherwise, notifications
  // are ignored.
  notificationFunc?(notification: Notification): void;

  // If set, called when a notice is received. Otherwise, notices are ignored.
  noticeFunc?(notice: Notice): void;
}

enum TXState {
  Idle,
  InTransaction,
  Failed,
}

interface BackendKeyData {
  pid: number;
  secretKey: number;
}

interface _FieldContext extends IFieldData {
  dataTypeOID: number;
  dataTypeSize: number;
  typeModifier: number;
  formatCode: number;
  data: Uint8Array;
  getParam(k: string): string | undefined;
}

const _dummy = new Uint8Array(1);

class PgFramer {
  private __completeFrames: Uint8Array[] = [];
  private __curFrame: Uint8Array | null = null;
  private __header: Uint8Array = new Uint8Array(5);

  private __bytesTotal: number = 0;
  private __bytesGot: number = 0;

  constructor() {
  }

  push(data: Uint8Array) {
    if (this.__bytesGot < 5) {
      let L = Math.min(data.length, 5-this.__bytesGot);
      for (let i=0;i<L;++i)
        this.__header[this.__bytesGot+i] = data[i];
      this.__bytesGot += L;
      if (this.__bytesGot < 5)
        return;
      data = data.subarray(L);
      this.__bytesTotal = ((this.__header[1]<<24) + (this.__header[2]<<16) + (this.__header[3]<<8) + this.__header[4]) + 1;
      this.__curFrame = new Uint8Array(this.__bytesTotal);
      for (let i=0; i<5; ++i)
        this.__curFrame[i] = this.__header[i];
    }

    let rem = this.__bytesTotal - this.__bytesGot;
    if (rem > 0 && data.length > 0) {
      const additional = data.subarray(0, Math.min(data.length, rem));

      const f = this.__curFrame as Uint8Array;
      const offs = this.__bytesGot;
      for (let i=0, L=additional.length; i<L; ++i)
        f[offs+i] = additional[i];

      this.__bytesGot += additional.length;
      rem -= additional.length;
      data = data.subarray(additional.length);
    }

    if (!rem) {
      this.__completeFrames.push(this.__curFrame as Uint8Array);
      this.__curFrame = null;
      this.__bytesGot = this.__bytesTotal = 0;
    }

    if (data.length > 0)
      this.push(data);
  }

  pop(): Uint8Array | null {
    if (this.__completeFrames.length === 0)
      return null;
    const f = this.__completeFrames[0];
    this.__completeFrames = this.__completeFrames.slice(1);
    return f;
  }
}


class PgConnection implements ILLDBConnection {
  private __args: IPgConnectionArgs;
  private __conn: IConn;
  private __serverParams: {[name: string]: string} = {};
  private __txState: TXState = TXState.Idle;
  private __handshakeDone: boolean = false;
  private __backendKeyData: BackendKeyData | null = null;
  private __closed: boolean = false;
  private __currentTx: PgConnectionTx | null = null;
  private __rowsOpen: boolean = false;
  private __serializeCtx: _FieldContext;
  private __framer: PgFramer = new PgFramer();
  private __txBuf: ArrayBuffer = new ArrayBuffer(256);
  private __txBufPos: number = 0;

  constructor(args: IPgConnectionArgs, conn: IConn) {
    this.__args = Object.freeze(args);
    this.__conn = conn;
    this.__serializeCtx = {
      dataTypeOID: 0, dataTypeSize: 0, typeModifier: 0, formatCode: 0, data: _dummy,
      getParam: this.__getParam.bind(this)};
  }


  /* 1. Initial Handshake {{{2
   * --------------------
   */

  // Startup handshake. Completed before returning PgConnection.
  async __handshake(): Promise<void> {
    if (this.__handshakeDone)
      throw new Error(`handshake already performed`);

    this.__handshakeDone = true;

    // Send startup message.
    this.__txStartup();
    await this.__flushTxBuffers();

    // Authentication loop.
    let doneAuth = false;
    while (!doneAuth) {
      const msg = await this.__rxMessage();
      const mtype = getMessageType(msg);

      switch (mtype) {
      case MessageType.AuthenticationRequest: // Authentication Request
        const req = this.__parseAuthenticationRequest(msg);
        if (req.type === '') {
          doneAuth = true;
          break;
        }

        const cspec = this.__args.connectionSpec as ConnectionSpec;
        switch (req.type) {
        case 'plain':
          this.__txPasswordResponse(cspec.password);
          await this.__flushTxBuffers();

        case 'md5':
          // 'md5'+ md5(md5(password+username)+random-salt)
          const h = crypto.createHash('md5');
          h.update(cspec.password + cspec.userName);
          const inner = h.digest();
          const h2 = crypto.createHash('md5');
          h2.update(inner);
          h2.update(new Buffer(req.salt as Uint8Array));
          const v = 'md5' + h2.digest('hex');

          this.__txPasswordResponse(v);
          await this.__flushTxBuffers();

        default:
          throw new Error(`unsupported authentication method requested`);
        }

      default:
        if (!this.__rxHandleCommon(msg))
          throw new Error(`unexpected incoming message type ${mtype} during handshake`);
      }
    }

    // Process informational messages from server.
    let doneInit = false;
    while (!doneInit) {
      const msg = await this.__rxMessage();
      const mtype = getMessageType(msg);

      switch (mtype) {
      case MessageType.BackendKeyData: // Backend Key Data
        this.__backendKeyData = this.__parseBackendKeyData(msg);
        break;
      case MessageType.ParameterStatus: // Parameter Status
        const [paramName, paramValue] = this.__parseParameterStatus(msg);
        this.__updateParam(paramName, paramValue);
        break;
      case MessageType.ReadyForQuery: // Ready for Query
        this.__txState = this.__parseReadyForQuery(msg);
        doneInit = true;
        break;
      default:
        if (!this.__rxHandleCommon(msg))
          throw new Error(`unexpected incoming message type ${mtype} during handshake`);
      }
    }

    // Done.
  }

  // }}}2


  __rxHandleCommon(msg: Uint8Array): boolean {
    const mtype = getMessageType(msg);
    switch (mtype) {
      case MessageType.ErrorResponse: {
        const r = this.__parseErrorResponse(msg);
        const err = new PgError(r);
        throw err;
      }
      case MessageType.NoticeResponse: {
        const r = this.__parseNoticeResponse(msg);
        this.__logNotice(r);
        return true;
      }
      case MessageType.NotificationResponse: {
        const r = this.__parseNotificationResponse(msg);
        this.__handleNotification(r);
        return true;
      }
      default:
        return false;
    }
  }

  private __handleNotification(r: Notification) {
    if (this.__args.notificationFunc)
      this.__args.notificationFunc(r);
  }

  private __logNotice(notice: Notice) {
    if (this.__args.noticeFunc)
      this.__args.noticeFunc(notice);
  }

  private __updateParam(paramName: string, paramValue: string) {
    this.__serverParams[paramName] = paramValue;
  }

  private __getParam(k: string): string | undefined {
    return this.__serverParams[k];
  }


  private __startupParams(): {[k: string]: string} {
    const spec = this.__args.connectionSpec as ConnectionSpec;
    return {
      user: spec.userName,
      database: spec.dbName,
      application_name: 'SQLAPI-Pg',
      client_encoding: 'UTF8',
      datestyle: 'ISO, YMD',
      //extra_float_digits: 3,
    };
  }


  /* 2. Message Transmission {{{2
   * -----------------------
   */

  private __getTxBufferSpace(len: number): DataView {
    const bufLen = this.__txBuf.byteLength;
    const p = this.__txBufPos;
    if ((bufLen - p) < len) {
      const b = new ArrayBuffer(Math.max(p+len, bufLen*2));
      const oldBuf = new Uint8Array(this.__txBuf);
      const b_ = new Uint8Array(b);
      for (let i=0; i<bufLen; ++i)
        b_[i] = oldBuf[i];
      this.__txBuf = b;
    }

    //this.__txBufPos += len;
    return new DataView(this.__txBuf, p, len);
  }

  private __confirmTxBufferSpace(dv: DataView) {
    this.__txBufPos = dv.byteOffset + dv.byteLength;
  }

  private async __flushTxBuffers(): Promise<void> {
    await this.__conn.write(new Uint8Array(this.__txBuf, 0, this.__txBufPos));
    this.__txBufPos = 0;
  }


  /*
        Startup Message (NOTYPE):
          4  si    Protocol Version (0x00030001)
          One or more parameters:
             zstr  Parameter Name ("user", "database", "options")
             zstr  Parameter Value
   */
  private __txStartup() {
    const params = this.__startupParams();
    const kvs: Uint8Array[] = [];

    // Compute length of message.
    let len = 4+4+1; // Length+Protocol Version+Terminating Zero Byte. This message has no type byte.
    for (const k in params) {
      const ka = utf8.encode(k);
      const va = utf8.encode(params[k]);
      kvs.push(ka);
      kvs.push(va);
      len += ka.length + va.length + 2; // Key and value plus zero terminators for each.
    }

    const av = this.__getTxBufferSpace(len);
    av.setInt32(0, len);        // Message length.
    av.setInt32(4, 0x00030000); // Protocol version.

    let pos = 8;
    for (const a of kvs) {
      copyBytesZ(av, pos, a);
      pos += a.length + 1; // data plus zero terminator
    }

    this.__confirmTxBufferSpace(av);
  }


  /*
        SSL Request Message (NOTYPE):
          4  si    SSL Request Code (0x04D2162F)
   */
  /*private async __txSSLRequest(): Promise<void> {
    const len = 4+4; // Length+SSL Request Psuedoversion. This message has no type byte.

    const a = new Uint8Array(len);
    const av = new DataView(a.buffer);
    av.setInt32(0, len);
    av.setInt32(4, 0x04D2162F); // SSL Request Psuedoversion.

    await this.__txRawMessage(a);
  }*/


  /*
        Password Response ('p'):
          zstr  Password (possibly encrypted)
   */
  private __txPasswordResponse(password: string) {
    const pa = utf8.encode(password);

    const len = 1+4+pa.length+1;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, 0x70 /* p */);
    av.setUint32(1, len-1);
    copyBytesZ(av, 5, pa);

    this.__confirmTxBufferSpace(av);
  }


  /*
        > Parse ('P')
            zstr  Name of destination prepared statement
            zstr  Query string to be parsed
            2  ui  Number of parameter data types
            For each parameter for which a data type is to be specified:
              4  ui  OID of parameter data type (0: unspecified)
   */
  private __txParse(statementName: string, queryText: string, paramTypes: number[]) {
    const statementNameA = utf8.encode(statementName);
    const queryTextA = utf8.encode(queryText);

    const len = 1+4+statementNameA.length+1+queryTextA.length+1+2+paramTypes.length*4;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, 0x50 /* P */);
    av.setUint32(1, len-1);
    let pos = 5;
    copyBytesZ(av, pos, statementNameA);
    pos += statementNameA.length+1;
    copyBytesZ(av, pos, queryTextA);
    pos += queryTextA.length+1;
    av.setUint16(pos, paramTypes.length);
    pos += 2;
    for (const p of paramTypes) {
      av.setUint32(pos, p);
      pos += 4;
    }
    this.__confirmTxBufferSpace(av);
  }


  /*
        > Bind ('B')
            zstr  Destination Portal Name ("": unnamed portal)
            zstr  Source Prepared Statement ("": unnamed prepared statement)
          2 ui    Number of parameter format codes (0: text for all, 1: use same format code for all parameters)
          Zero or more format codes:
            2  ui  Format code (0: text, 1: binary)
          2  ui   Number of parameters for query
          For each parameter:
            4  ui  Length of parameter value (-1: NULL value)
            ...    Parameter value data (NULL: no bytes)
          2  ui  Number of result-column format codes (0: no result columns/text for all, 1: apply same format code for all)
          Zero or more format codes:
            2  ui  Format code (0: text, 1: binary)
   */
  private __txBind(portalName: string, statementName: string, formatCodes: number[], params: (Uint8Array | null)[], resultFormatCodes: number[]) {
    const portalNameA = utf8.encode(portalName);
    const statementNameA = utf8.encode(statementName);

    let len = 1+4+portalNameA.length+1+statementNameA.length+1+2+2*formatCodes.length+2+4*params.length+2+2*resultFormatCodes.length;
    for (const p of params)
      len += p ? p.length : 0;

    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, 0x42 /* B */);
    av.setUint32(1, len-1);
    let pos = 5;
    copyBytesZ(av, pos, portalNameA);
    pos += portalNameA.length+1;
    copyBytesZ(av, pos, statementNameA);
    pos += statementNameA.length+1;
    av.setUint16(pos, formatCodes.length);
    pos += 2;
    for (const c of formatCodes) {
      av.setUint16(pos, c);
      pos += 2;
    }
    av.setUint16(pos, params.length);
    pos += 2;
    for (const p of params) {
      av.setUint32(pos, p ? p.length : 0xFFFFFFFF);
      pos += 4;
      if (p) {
        copyBytesZ(av, pos, p);
        pos += p.length;
      }
    }

    av.setUint16(pos, resultFormatCodes.length);
    pos += 2;
    for (const c of resultFormatCodes) {
      av.setUint16(pos, c);
      pos += 2;
    }

    this.__confirmTxBufferSpace(av);
  }


  /*
        > Portal Describe ('D')
            1  ui  Type ('S': describe prepared statement, 'P': describe portal)
            zstr   Name of prepared statement or portal to describe ("": unnamed object)
   */
  private __txDescribe(portal: boolean, name: string) {
    this.__txDescribe_(portal, name, 0x44 /* D */);
  }

  private __txDescribe_(portal: boolean, name: string, messageType: number) {
    const nameA = utf8.encode(name);

    const len = 1+4+1+nameA.length+1;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, messageType);
    av.setUint32(1, len-1);
    let pos = 5;
    av.setUint8(pos, portal ? 0x50 /* P */ : 0x53 /* S */);
    pos += 1;
    copyBytesZ(av, pos, nameA);
    pos += nameA.length+1;

    this.__confirmTxBufferSpace(av);
  }


  /*
        > Flush ('H')
           (no data)
   */
  private __txFlush() {
    this.__txEmptyMsg(MessageType.Flush);
  }


  /*
        > Sync ('S')
           (no data)
   */
  private __txSync() {
    this.__txEmptyMsg(MessageType.Sync);
  }


  private __txEmptyMsg(messageType: number) {
    const len = 1+4;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, messageType);
    av.setUint32(1, len-1);

    this.__confirmTxBufferSpace(av);
  }


  /*
        > Execute ('E')
           zstr  Name of portal to execute ("": unnamed portal)
           4  ui  Maximum number of rows to return (0: unlimited)
   */
  private __txExecute(portalName: string, maxRows: number) {
    const portalNameA = utf8.encode(portalName);

    const len = 1+4+portalNameA.length+1+4;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, 0x45 /* E */);
    av.setUint32(1, len-1);
    let pos = 5;

    copyBytesZ(av, pos, portalNameA);
    pos += portalNameA.length+1;

    av.setUint32(pos, maxRows);
    pos += 4;

    this.__confirmTxBufferSpace(av);
  }


  /*
        > Close ('C')
            1  ui  Close Object Type ('S': prepared statement, 'P': portal)
            zstr   Name of prepared statement or portal to close ("": unnamed object)
   */
  private __txClose(portal: boolean, name: string) {
    return this.__txDescribe_(portal, name, 0x43 /* C */);
  }


  /*
        > Query ('Q')
            zstr  Query Text
   */
  private __txQuery(sqlText: string) {
    const sqlTextA = utf8.encode(sqlText);

    const len = 1+4+sqlTextA.length+1;
    const av = this.__getTxBufferSpace(len);
    av.setUint8(0, 0x51 /* Q */);
    av.setUint32(1, len-1);
    let pos = 5;

    copyBytesZ(av, pos, sqlTextA);

    this.__confirmTxBufferSpace(av);
  }


  /* 3. Message Parsing {{{2
   * ------------------
   */


  private async __rxMessage(): Promise<Uint8Array> {
    while (true) {
      const msg = this.__framer.pop();
      if (msg)
        return msg;

      const data = await this.__conn.read(8192);
      this.__framer.push(data);
    }
  }

  /*
        Authentication Request Message ('R'):
          4  si    Authentication Type (0: Authentication OK, 2: Kerberos v5, 3: Plain, 5: MD5, 6: SCM, 7: GSSAPI, 8: GSSAPI-Continue, 9: SSPI)
          ... Type-specific data:
            Authentication OK:
              (no data)
            Plain:
              (no data)
            MD5:
              4 bytes   salt

   */
  private __parseAuthenticationRequest(a: Uint8Array): AuthenticationRequest {
    if (a.length < 9)
      throw new Error(`unexpected length when processing Authentication Request message`);

    const av = new DataView(a.buffer);
    const atype = av.getUint32(5);
    switch (atype) {
      case 0: // Authentication OK
        return {type: ''};
      case 3: // Plain
        return {type: 'plain'};
      case 5: // MD5
        if (a.length < 13)
          throw new Error(`unexpected length when processing Authentication Request message`);
        return {type: 'md5', salt: a.subarray(9, 13)};
      default:
        throw new Error(`unsupported authentication type requested: ${atype}`);
    }
  }


  /*

        Error Response ('E'):
          One or more fields:
            1  ui    Field type (0x00: end of field list, 'S': severity, 'V': severity-unlocalized, 'C': SQLSTATE, 'M': human-readable message, 'D': detail message, 'H': hint, 'P': position, 'p': internal position, 'q': internal qhery, 'W': where, 's': schema name, 't': table name, 'c': column name, 'd': data type name, 'n': constraint name, 'F': filename, 'L': line number, 'R': routine)
               zstr  Field data

        NoticeResponse ('N')
          For each field:
            1  ui  Field type (0: end of fields)
            zstr   Field value
   */
  private __parseNotice(a: Uint8Array): Notice {
    if (a.length < 7)
      throw new Error(`unexpected length when processing Error/Notice Response message`);

    const fields = {} as Notice;
    const av = new DataView(a.buffer);
    let pos = 5;
    while (pos < a.length) {
      const fieldType = av.getUint8(pos);
      if (fieldType === 0)
        break;

      ++pos;
      let fieldData: string;
      [fieldData, pos] = readString(av, pos);

      const ch = String.fromCharCode(fieldType);
      const key = errorResponseFieldMapping[ch] || ch;
      (fields as any)[key] = fieldData;
    }

    return fields;
  }

  private __parseNoticeResponse(d: Uint8Array): Notice {
    return this.__parseNotice(d);
  }

  private __parseErrorResponse(d: Uint8Array): Notice {
    return this.__parseNotice(d);
  }


  /*
        < NotificationResponse ('A')
          4  ui  Process ID of backend process
          zstr   Channel Name
          zstr   Channel Data
   */
  private __parseNotificationResponse(a: Uint8Array): Notification {
    if (a.length < 11)
      throw new Error(`unexpected length when processing Notification Response message`);

    const av = new DataView(a.buffer);
    const pid = av.getUint32(5);
    let pos = 9;
    let channelName: string
    let channelData: string;
    [channelName, pos] = readString(av, pos);
    [channelData, pos] = readString(av, pos);

    return {pid, channelName, channelData};
  }


  /*
        < ParameterStatus ('S')
          zstr  Parameter being reported
          zstr  Current parameter value
   */
  private __parseParameterStatus(a: Uint8Array): [string, string] {
    if (a.length < 7)
      throw new Error(`unexpected length when processing Parameter Status message`);

    const av = new DataView(a.buffer);

    let pos = 5;
    let paramName: string;
    let paramValue: string;
    [paramName, pos] = readString(av, pos);
    [paramValue, pos] = readString(av, pos);
    return [paramName, paramValue];
  }


  /*
        < ReadyForQuery ('Z')
          1  ui  Transaction Status Indicator ('I': idle, no transaction, 'T': in transaction, 'E': in failed transaction)
   */
  private __parseReadyForQuery(a: Uint8Array): TXState {
    if (a.length < 6)
      throw new Error(`unexpected length when processing Ready for Query message`);

    const av = new DataView(a.buffer);
    const status = av.getUint8(5);
    switch (status) {
      case 0x49 /* I - Idle */:
        return TXState.Idle;
      case 0x54 /* T - In Transaction */:
        return TXState.InTransaction;
      case 0x45 /* E - In Failed Transaction */:
        return TXState.Failed;
      default:
        throw new Error(`unexpected transaction status byte`);
    }
  }


  /*
        < CommandComplete ('C')
           zstr  Command Tag (usually a single word indicating SQL command completed, e.g. "SELECT".
                              for INSERT: "INSERT oid numRows"
                              for DELETE: "DELETE numRows"
                              for UPDATE: "UPDATE numRows"
                              for SELECT: "SELECT numRows")

   */
  private __parseCommandComplete(a: Uint8Array): string {
    if (a.length < 6)
      throw new Error(`unexpected length when processing Command Complete message`);

    const av = new DataView(a.buffer);
    const [commandTag, ] = readString(av, 5);
    return commandTag;
  }


  /*
        BackendKeyData
          4  ui  Process ID of backend
          4  ui  Secret key of backend
   */
  private __parseBackendKeyData(a: Uint8Array): BackendKeyData {
    if (a.length < 13)
      throw new Error(`unexpected length when processing Backend Key Data message`);

    const av = new DataView(a.buffer);
    const pid = av.getUint32(5);
    const secretKey = av.getUint32(9);
    return {pid, secretKey};
  }


  /*
        < CopyOutResponse ('H')
           1  ui  Copy Format (0: textual, 1: binary)
           2  ui  Number of columns
           For each column:
             2  ui  Column Format (0: textual, 1: binary)
   */
  /*private __parseCopyOutResponse(a: Uint8Array): MsgCopyOutResponse {
    if (a.length < 8)
      throw new Error(`unexpected length when processing Copy Out Response message`);

    const av = new DataView(a.buffer);
    const copyFormat = av.getUint8(5);
    const numColumns = av.getUint16(6);
    let pos = 8;
    let columnFormats: number[] = [];
    for (let i=0; i<numColumns; ++i) {
      const columnFormat = av.getUint16(pos);
      pos += 2;
      columnFormats.push(columnFormat);
    }

    return {copyFormat, columnFormats};
  }*/


  /*

        < ParameterDescription ('t')
            2  ui  Number of parameters used by statement (can be zero)
            For each parameter:
              4  ui  Data Type OID

   */
  private __parseParameterDescription(a: Uint8Array): number[] {
    let oids: number[] = [];
    const av = new DataView(a.buffer);
    const numParams = av.getUint16(5);
    let pos = 7;

    for (let i=0; i<numParams; ++i) {
      oids.push(av.getUint32(pos));
      pos += 4;
    }

    return oids;
  }


  /*
        < RowDescription ('T')
            2  ui  Number of fields in a row (can be zero)
            For each field:
              zstr  Field name
              4  ui  Table OID (or zero if field is not from a table column)
              4  ui  Column Attribute Number (or zero if field is not from a table column)
              4  ui  Data Type OID
              2  si  Data Type Size (negative values: variable-width type. This is the conceptual maxlength configured as part of the type (e.g. VARCHAR(64)), it has nothing to do with actual field encoding on the wire.)
              4  ui  Type modifier (interpretation is type-specific)
              2  ui  Format code for field (0: text, 1: binary)
   */
  private __parseRowDescription(a: Uint8Array): MsgFieldDescription[] {
    if (a.length < 7)
      throw new Error(`unexpected length when processing Row Description message`);

    const fields: MsgFieldDescription[] = [];

    const av = new DataView(a.buffer);
    const numFields = av.getUint16(5);
    let pos = 7;
    for (let i=0; i<numFields; ++i) {
      let fieldName: string;
      [fieldName, pos] = readString(av, pos);
      const tableOID = av.getUint32(pos);
      pos += 4;
      const columnAttributeNo = av.getUint16(pos);
      pos += 2;
      const dataTypeOID = av.getUint32(pos);
      pos += 4;
      const dataTypeSize = av.getUint16(pos);
      pos += 2;
      const typeModifier = av.getUint32(pos);
      pos += 4;
      const formatCode = av.getUint16(pos);
      pos += 2;

      fields.push({index: i, fieldName, tableOID, columnAttributeNo, dataTypeOID, dataTypeSize, typeModifier, formatCode});
    }

    return fields;
  }


  /*
        < DataRow ('D')
           2  ui  Number of columns (possibly 0)
           For each column:
             4  ui  Length of column value (-1: NULL value)
             ...    Column value data (NULL: no bytes)
   */
  private __parseDataRow(a: Uint8Array, fields: MsgFieldDescription[]): any[] {
    if (a.length < 7)
      throw new Error(`unexpected length when processing Data Row message`);

    const av = new DataView(a.buffer);
    const numColumns = av.getUint16(5);
    let pos = 7;

    const values: any[] = [];

    for (let i=0; i<numColumns; ++i) {
      const valueLen = av.getUint32(pos);
      pos += 4;
      if (valueLen === 0xFFFFFFFF) {
        values.push(null);
        continue;
      }

      values.push(this.__deserializeFieldValue(a.subarray(pos, pos+valueLen), fields[i]));
      pos += valueLen;
    }

    return values;
  }

  // Deserializes the raw binary data constituting the value of a field of a row. Uses the
  // field (which must be passed from the data obtained by parseRowDescription) to determine
  // how the data should be deserialized.
  private __deserializeFieldValue(fieldData: Uint8Array, field: MsgFieldDescription): any {
    if (field.formatCode !== 1)
      throw new Error(`unexpected format code when deserializing field value: expected binary format`);

    const h = _getDeserializer(field.dataTypeOID);
    if (!h)
      throw new Error(`Cannot find deserialization handler for data type OID ${field.dataTypeOID}`);

    this.__serializeCtx.data = fieldData;
    this.__serializeCtx.dataTypeOID = field.dataTypeOID;
    this.__serializeCtx.dataTypeSize = field.dataTypeSize;
    this.__serializeCtx.typeModifier = field.typeModifier;
    this.__serializeCtx.formatCode = field.formatCode;
    return h(this.__serializeCtx);
  }


  /* Public Interface Methods {{{2
   * ------------------------
   */

  async close(): Promise<void> {
    if (this.__closed)
      return;

    this.__closed = true;
    await this.__conn.close();
  }

  async ping(ctx: IContext): Promise<void> {
  }

  async begin(ctx: IContext, options: ILLDBConnectionTxOptions={}): Promise<ILLDBConnectionTx> {
    if (this.engaged)
      throw new Error(`A transaction is already in progress.`);

    await this.exec(ctx, 'BEGIN', []);
    const tx = new PgConnectionTx(this.__finishTransaction.bind(this));
    this.__currentTx = tx;
    return tx;
  }

  private async __finishTransaction(tx: PgConnectionTx, doCommit: boolean): Promise<void> {
    if (tx !== this.__currentTx)
      return;

    this.__currentTx = null;
    await this.exec(background(), doCommit ? 'COMMIT' : 'ROLLBACK', []);
  }

  exec(ctx: IContext, sqlText: string, sqlArgs: any[]): Promise<ILLDBResult> {
    if (sqlArgs.length === 0)
      return this.__execSimple(ctx, sqlText);
    else
      return this.__execWithArgs(ctx, sqlText, sqlArgs);
  }

  private async __execSimple(ctx: IContext, sqlText: string): Promise<ILLDBResult> {
    try {
      this.__rowsOpen = true;
      await this.__issueQuery(ctx, sqlText);

      let gotReady = false;
      let tag: string | undefined = undefined;

      while (!gotReady) {
        const msg = await this.__rxMessage();
        const mtype = getMessageType(msg);

        switch (mtype) {
        case MessageType.CopyOutResponse:
        case MessageType.RowDescription:
        case MessageType.DataRow:
        case MessageType.NoData:
          // This is exec, so ignore any response result set.
          break;

        case MessageType.CommandComplete:
          if (tag !== undefined)
            throw new Error(`got multiple CommandComplete commands`);

          tag = this.__parseCommandComplete(msg);
          break;

        case MessageType.ReadyForQuery:
          this.__txState = this.__parseReadyForQuery(msg);
          gotReady = true;
          break;

        case MessageType.EmptyQueryResponse:
          throw new Error(`query string was empty`);

        default:
          if (!this.__rxHandleCommon(msg))
            throw new Error(`unexpected incoming message type ${mtype} during transaction commit/rollback`);
          break;
        }
      }

      return {tag}; // TODO: rowsAffected
    } finally {
      this.__rowsOpen = false;
    }
  }

  private async __execWithArgs(ctx: IContext, sqlText: string, sqlArgs: any[]): Promise<ILLDBResult> {
    this.__rowsOpen = true;
    try {
      await this.__issueQueryWithArgs(ctx, sqlText, sqlArgs);

      let gotReady = false;
      let tag: string | undefined = undefined;

      while (!gotReady) {
        const msg = await this.__rxMessage();
        const mtype = getMessageType(msg);
        switch (mtype) {
        case MessageType.CopyOutResponse:
        case MessageType.RowDescription:
        case MessageType.DataRow:
        case MessageType.NoData:
          // This is exec, so ignore any response result set.
          break;

        case MessageType.ParseComplete:
        case MessageType.BindComplete:
        case MessageType.CloseComplete:
          break;

        case MessageType.CommandComplete:
          if (tag !== undefined)
            throw new Error(`got multiple CommandComplete commands`);

          tag = this.__parseCommandComplete(msg);
          break;

        case MessageType.ReadyForQuery:
          this.__txState = this.__parseReadyForQuery(msg);
          gotReady = true;
          break;

        case MessageType.EmptyQueryResponse:
          throw new Error(`query string was empty`);

        default:
          if (!this.__rxHandleCommon(msg))
            throw new Error(`unexpected incoming message type ${mtype} during execution`);
          break;
        }
      }

      return {tag};
    } finally {
      this.__rowsOpen = false;
    }
  }

  private async __issueQuery(ctx: IContext, sqlText: string): Promise<void> {
    this.__txQuery(sqlText);
    await this.__flushTxBuffers();
  }

  private async __issueQueryWithArgs(ctx: IContext, sqlText: string, sqlArgs: any[]): Promise<void> {
    let paramTypeOIDs: number[] | null = null;

    // Send all the commands up front to avoid multiple round trips.
    try {
      this.__txParse('', sqlText, []);
      this.__txDescribe(false, '');
      this.__txFlush();
      await this.__flushTxBuffers();

      let gotReady = false;
      while (!gotReady) {
        const msg = await this.__rxMessage();
        const mtype = getMessageType(msg);
        switch (mtype) {
        case MessageType.ParseComplete:
          break;
        case MessageType.ParameterDescription:
          paramTypeOIDs = this.__parseParameterDescription(msg);
          break;
        case MessageType.NoData:
        case MessageType.RowDescription:
          gotReady = true;
          break;
        default:
          if (!this.__rxHandleCommon(msg))
            throw new Error(`unexpected incoming message type ${mtype} during execution`);
          break;
        }
      }

      if (!paramTypeOIDs)
        throw new Error(`did not receive parameter types`);

      this.__txBind('', '', allBinary, this.__serializeParams(sqlArgs, paramTypeOIDs), allBinary);
      this.__txDescribe(true, '');
      this.__txExecute('', 0);
      this.__txClose(false, ''); // Closing a statement closes derived portals too.
    } finally {
      this.__txSync();
      await this.__flushTxBuffers();
    }
  }

  private __serializeParams(sqlArgs: any[], typeOIDs: number[]): Uint8Array[] {
    if (typeOIDs.length !== sqlArgs.length)
      throw new Error(`wrong number of SQL arguments: passed ${sqlArgs.length}, expected ${typeOIDs.length}`);

    const a = [];
    for (let i=0; i<sqlArgs.length; ++i)
      a.push(this.__serializeParam(sqlArgs[i], typeOIDs[i]));

    return a;
  }

  private __serializeParam(sqlArg: any, typeOID: number): Uint8Array {
    const sz = _getSerializer(typeOID);
    if (!sz)
      throw new Error(`cannot find serializer for type OID ${typeOID}`);

    this.__serializeCtx.dataTypeOID = typeOID;
    const r = sz(sqlArg, this.__serializeCtx);
    if (r === undefined)
      throw new Error(`serializer for type OID ${typeOID} failed to serialize "${sqlArg}"`);

    return r;
  }

  private async __query(ctx: IContext, sqlText: string, sqlArgs: any[]): Promise<ILLDBRows> {
    const self = this;
    let fields: MsgFieldDescription[] | undefined = undefined;
    let rows: PgRows | null = null;
    const gen = (async function*() {
      self.__rowsOpen = true;
      let skipRest = false;
      try {
        await self.__issueQueryWithArgs(ctx, sqlText, sqlArgs);

        let gotReady = false;
        let tag: string | undefined = undefined;

        while (!gotReady) {
          const msg = await self.__rxMessage();
          const mtype = getMessageType(msg);
          switch (mtype) {
          //case MessageType.CopyOutResponse:
          case MessageType.RowDescription:
            if (fields !== undefined)
              throw new Error(`got multiple RowDescription commands`);

            fields = self.__parseRowDescription(msg);
            yield [];
            break;

          case MessageType.DataRow:
            if (fields === undefined)
              throw new Error(`got data row but not row description`);

            const rfields = self.__parseDataRow(msg, fields);
            if (!skipRest)
              if (yield rfields)
                skipRest = true;

            break;

          case MessageType.ParseComplete:
          case MessageType.BindComplete:
          case MessageType.CloseComplete:
            break;

          case MessageType.CommandComplete:
            if (tag !== undefined)
              throw new Error(`got multiple CommandComplete commands`);

            tag = self.__parseCommandComplete(msg);
            break;

          case MessageType.ReadyForQuery:
            self.__txState = self.__parseReadyForQuery(msg);
            gotReady = true;
            break;

          case MessageType.EmptyQueryResponse:
            throw new Error(`query string was empty`);

          default:
            if (!self.__rxHandleCommon(msg))
              throw new Error(`unexpected incoming message type ${mtype} during execution`);
              break;
          }
        }

        if (rows && tag !== undefined)
          rows.__setTag(tag);
      } finally {
        self.__rowsOpen = false;
      }
    }).call(this);

    await gen.next(); // get fields
    if (!fields)
      throw new Error(`no fields?`);

    const rows_ = new PgRows(this, gen, fields);
    rows = rows_;
    return rows_;
  }

  query(ctx: IContext, sqlText: string, sqlArgs: any[]): Promise<ILLDBRows> {
    //if (sqlArgs.length === 0)
    //  return this.__querySimple(ctx, sqlText);
    //else
      return this.__query(ctx, sqlText, sqlArgs);
  }

  get engaged(): boolean { return this.__rowsOpen; }

  toString(): string { return `[PgConnection: ${this.__conn}]`; }
}

class PgConnectionTx implements ILLDBConnectionTx {
  private __f: (doCommit: boolean) => Promise<void>;

  constructor(f: (doCommit: boolean) => Promise<void>) {
    this.__f = f;
  }

  rollback(): Promise<void> {
    return this.__f(false);
  }

  async commit(): Promise<void> {
    return this.__f(true);
  }

  toString(): string { return `[PgConnectionTx]`; }
}

class PgRows implements ILLDBRows {
  private __conn: PgConnection;
  private __gen: AsyncIterator<any[]>;
  private __columns: string[];
  private __done: boolean = false;
  private __tag: string | null = null;

  constructor(conn: PgConnection, gen: AsyncIterator<any[]>, fields: MsgFieldDescription[]) {
    this.__conn = conn;
    this.__gen = gen;
    this.__columns = fields.map(f => f.fieldName);
  }

  async close(): Promise<void> {
    if (this.done)
      return;

    this.__done = true;
    await this.__gen.next(true);
  }

  __setTag(tag: string) {
    this.__tag = tag;
  }

  get tag(): string | null { return this.__tag; }
  get columns(): string[] { return this.__columns; }
  get done(): boolean { return this.__done; }

  [Symbol.asyncIterator](): this { return this; }

  async next(): Promise<IteratorResult<any[]>> {
    if (this.done)
      throw new Error(`cannot advance PgRows which is already done`);

    const r = await this.__gen.next(false);
    if (r.done)
      this.__done = true;
    return r;
  }
}

async function tcpConnectViaArgs(ctx: IContext, args: IPgConnectionArgs): Promise<IConn> {
  const dialer_ = args.dialer || dialer;
  if (!dialer_)
    throw new Error(`no dialer`);

  return await dialer_.dial(ctx, 'tcp', (args.connectionSpec as ConnectionSpec).hostName);
}

const driver: ILLDBDriver = Object.freeze({
  async connect(ctx: IContext, args_: any): Promise<ILLDBConnection> {
    if (typeof args_ !== 'object')
      throw new Error(`Pg driver requires object as connection-time argument`);

    const args = Object.assign({}, args_) as IPgConnectionArgs;
    args.connectionSpec = ConnectionSpec.ensure(args.connectionSpec || '');

    const conn = await tcpConnectViaArgs(ctx, args);
    const pgc = new PgConnection(args, conn);
    await pgc.__handshake();
    return pgc;
  },
});
registerDriver('Pg', driver);
