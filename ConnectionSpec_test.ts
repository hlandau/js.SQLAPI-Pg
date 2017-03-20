import {ConnectionSpec, TLSMode} from "hlandau.SQLAPI-Pg/ConnectionSpec";
import * as chai from "chai";

chai.should();

describe('ConnectionSpec', () => {
  const env: {[k: string]: string} = {
    'PGDATABASE': 'my_db',
    'PGHOST': 'some.db.server',
    'PGPORT': '1234',
    'PGUSER': 'myUser',
    'PGPASSWORD': 'qh x',
    'PGSSLMODE': 'never',
  };

  describe('#fromString', () => {
    it('should parse a complex, fully-specified DSN correctly', () => {
      const spec = ConnectionSpec.fromString('host=some.host.name port=5439 dbname=some_db user=foo password=C0mplex P@ssword With Spaces!');

      spec.args.should.eql({
        hostName: 'some.host.name:5439',
        dbName:   'some_db',
        userName: 'foo',
        password: 'C0mplex P@ssword With Spaces!',
        tlsMode:  TLSMode.Prefer,
      });
    });

    it('should parse ports correctly', () => {
      const spec = ConnectionSpec.fromString('port=5439 host=some.host.name dbname=some_db user=foo password=abc');

      spec.args.should.eql({
        hostName: 'some.host.name:5439',
        dbName: 'some_db',
        userName: 'foo',
        password: 'abc',
        tlsMode: TLSMode.Prefer,
      });
    });

    it('should handle specification of only port correctly', () => {
      const spec = ConnectionSpec.fromString('port=5439 dbname=some_db user=foo password=abc');

      spec.args.should.eql({
        hostName: 'localhost:5439',
        dbName: 'some_db',
        userName: 'foo',
        password: 'abc',
        tlsMode: TLSMode.Prefer,
      });
    });

    it('should handle TLS mode specification correctly', () => {
      const spec = ConnectionSpec.fromString('host=some.host.name dbname=some_db sslmode=require user=foo password=abc');

      spec.args.should.eql({
        hostName: 'some.host.name:5432',
        dbName: 'some_db',
        tlsMode: TLSMode.Require,
        userName: 'foo',
        password: 'abc',
      });
    });

    it('should handle environment variable-based specification correctly', () => {
      const spec = ConnectionSpec.fromString('', {env: (k: string): string | undefined => env[k]});

      spec.args.should.eql({
        dbName: 'my_db',
        hostName: 'some.db.server:1234',
        userName: 'myUser',
        password: 'qh x',
        tlsMode: TLSMode.Never,
      });
    });

    it('should handle environment variable-based inheritance correctly', () => {
      const spec = ConnectionSpec.fromString('port=2345 dbname=xoxo sslmode=require', {env: (k: string): string | undefined => env[k]});

      spec.args.should.eql({
        dbName: 'xoxo',
        hostName: 'some.db.server:2345',
        userName: 'myUser',
        password: 'qh x',
        tlsMode: TLSMode.Require,
      });
    });

    it('should handle URLs correctly', () => {
      const spec = ConnectionSpec.fromString('postgresql://myUser:aux@some.db.server/somedb');

      spec.args.should.eql({
        dbName: 'somedb',
        hostName: 'some.db.server:5432',
        userName: 'myUser',
        password: 'aux',
        tlsMode: TLSMode.Prefer,
      });
    });

    it('should handle URLs with ports correctly', () => {
      const spec = ConnectionSpec.fromString('postgresql://myUser:aux@some.db.server:2345/somedb');

      spec.args.should.eql({
        dbName: 'somedb',
        hostName: 'some.db.server:2345',
        userName: 'myUser',
        password: 'aux',
        tlsMode: TLSMode.Prefer,
      });
    });

    it('should handle URLs inheriting authentication information from environment variables correctly', () => {
      const spec = ConnectionSpec.fromString('postgresql://some.db.server:2345/somedb', {env: (k: string): string | undefined => env[k]});

      spec.args.should.eql({
        dbName: 'somedb',
        hostName: 'some.db.server:2345',
        userName: 'myUser',
        password: 'qh x',
        tlsMode: TLSMode.Never,
      });
    });

    it('should handle URLs without explicit ports inheriting information from environment variables correctly', () => {
      const spec = ConnectionSpec.fromString('postgresql://some.db.server/somedb?sslmode=require', {env: (k: string): string | undefined => env[k]});

      spec.args.should.eql({
        dbName: 'somedb',
        hostName: 'some.db.server:1234',
        userName: 'myUser',
        password: 'qh x',
        tlsMode: TLSMode.Require,
      });
    });
  });
});
