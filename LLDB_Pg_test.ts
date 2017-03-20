import "hlandau.SQLAPI-Pg/LLDB_Pg";
import {ConnectionSpec} from "hlandau.SQLAPI-Pg/ConnectionSpec";
import {connect, ILLDBConnection} from "hlandau.SQLAPI/LLDB";
import {background} from "hlandau.Context";
import * as chai from "chai";

chai.should();

process.on('warning', (w: any) => {
  console.log(w);
});

let _conn: ILLDBConnection | null = null;
async function getConn(): Promise<ILLDBConnection> {
  if (!_conn) {
    const spec = ConnectionSpec.fromString('');
    _conn = await connect(background(), 'Pg', {connectionSpec: spec});
  }

  return _conn;
}

async function closeConn(): Promise<void> {
  if (!_conn)
    return;

  await _conn.close();
  _conn = null;
}

describe('PgConnection', () => {
  it('should connect and disconnect correctly', async () => {
    await getConn();
    await closeConn();
  });

  it('should exec simple statements correctly', async () => {
    const conn = await getConn();
    await conn.exec(background(), 'CREATE TABLE IF NOT EXISTS xoxo(id int)', []);
  });

  it('should exec complex statements correctly', async () => {
    const conn = await getConn();
    await conn.exec(background(), 'DELETE FROM xoxo WHERE id=$1', [42]);
  });

  it('should issue simple queries correctly (empty table)', async () => {
    const conn = await getConn();
    const r = await conn.query(background(), 'SELECT * FROM xoxo', []);
    (await r.next()).done.should.equal(true);
    r.done.should.equal(true);
  });

  it('should issue simple queries correctly (with results)', async () => {
    const conn = await getConn();
    const r = await conn.query(background(), 'SELECT typname, oid FROM pg_type', []);
    const corrects: {[k: string]: number} = {bool: 16, bytea: 17, char: 18, int8: 20, int2: 21, int4: 23, text: 25, json: 114};
    let actual: {[k: string]: number} = {};
    for await (const x of r as any) {
      const [name, oid] = x;
      if (corrects[name])
        actual[name] = oid;
    }
    r.done.should.equal(true);
    actual.should.deep.equal(corrects);
  });
});
