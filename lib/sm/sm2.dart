import 'dart:convert';
import 'dart:math';
import 'sm3.dart';
import 'utils/asn1.dart';
import 'utils/ec.dart';
import 'utils/utils.dart';

const C1C2C3 = 0;
const C1C3C2 = 1;

class SM2 {
  static final _EcParam _ecParam = _generateEcParam();
  static final Random _rng = Random.secure();

  static _EcParam _generateEcParam() {
    final p = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        radix: 16);
    final a = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        radix: 16);
    final b = BigInt.parse(
        '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
        radix: 16);
    final curve = ECCurveFp(p, a, b);

    const gxHex =
        '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    const gyHex =
        'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    final G = curve.decodePointHex('04$gxHex$gyHex');

    final n = BigInt.parse(
        'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        radix: 16);

    return _EcParam(curve: curve, G: G, n: n);
  }

  /// 生成随机数 k [1, n-1]
  static BigInt _randomK() {
    final int bitLength = _ecParam.n.bitLength;
    BigInt k;
    do {
      k = BigInt.zero;
      for (var i = 0; i < bitLength; i++) {
        final bit = _rng.nextBool() ? BigInt.one : BigInt.zero;
        k |= (bit << i);
      }
      k = k % (_ecParam.n - BigInt.one) + BigInt.one;
    } while (k <= BigInt.zero || k >= _ecParam.n);
    return k;
  }

  /// 标准签名
  static String signature(String msg, String privateKey,
      {bool der = false, String userId = '1234567812345678'}) {
    final pubKey = _getPublicKeyFromPrivateKey(privateKey);
    final e = BigInt.parse(_getHash(msg, pubKey, userId), radix: 16);
    final dA = BigInt.parse(privateKey, radix: 16);
    final dAInv = (dA + BigInt.one).modInverse(_ecParam.n);

    BigInt r, s, k;
    do {
      do {
        k = _randomK();
        final p1 = _ecParam.G!.multiply(k);
        r = (e + p1.getX().toBigInteger()) % _ecParam.n;
      } while (r == BigInt.zero || (r + k) == _ecParam.n);

      s = (dAInv * (k - r * dA)) % _ecParam.n;
    } while (s == BigInt.zero);

    if (der) return ASN1Utils.encodeDer(r, s);
    return leftPad(r.toRadixString(16), 64) + leftPad(s.toRadixString(16), 64);
  }

  /// 标准验签
  static bool verifySignature(String msg, String signHex, String publicKey,
      {bool der = false, String userId = '1234567812345678'}) {
    final e = BigInt.parse(_getHash(msg, publicKey, userId), radix: 16);

    BigInt r, s;
    if (der) {
      final obj = ASN1Utils.decodeDer(signHex);
      r = obj['r']!;
      s = obj['s']!;
    } else {
      r = BigInt.parse(signHex.substring(0, 64), radix: 16);
      s = BigInt.parse(signHex.substring(64), radix: 16);
    }

    if (r <= BigInt.zero || r >= _ecParam.n) return false;
    if (s <= BigInt.zero || s >= _ecParam.n) return false;

    final t = (r + s) % _ecParam.n;
    if (t == BigInt.zero) return false;

    final p1 = _ecParam.G!.multiply(s);
    final p2 = _ecParam.curve.decodePointHex(publicKey)!.multiply(t);
    final p = p1.add(p2);

    final R = (e + p.getX().toBigInteger()) % _ecParam.n;
    return R == r;
  }

  /// 加密 (C1 保留 04 前缀)
  static String encrypt(String msg, String publicKey,
      {int cipherMode = C1C3C2}) {
    final msgBytes = utf8.encode(msg);
    final pubPoint = _ecParam.curve.decodePointHex(publicKey)!;
    final k = _randomK();
    final c1Point = _ecParam.G!.multiply(k);
    final c1 = '04' +
        leftPad(c1Point.getX().toBigInteger().toRadixString(16), 64) +
        leftPad(c1Point.getY().toBigInteger().toRadixString(16), 64);

    final p = pubPoint.multiply(k);
    final x2 = SMUtils.hexStringToBytes(
        leftPad(p.getX().toBigInteger().toRadixString(16), 64));
    final y2 = SMUtils.hexStringToBytes(
        leftPad(p.getY().toBigInteger().toRadixString(16), 64));

    // KDF
    int ct = 1;
    int offset = 0;
    List<int> t = [];
    final z = [...x2, ...y2];
    void nextT() {
      t = SMUtils.hexStringToBytes(SM3.hashBytes([
        ...z,
        (ct >> 24) & 0xFF,
        (ct >> 16) & 0xFF,
        (ct >> 8) & 0xFF,
        ct & 0xFF
      ]));
      ct++;
      offset = 0;
    }

    nextT();
    for (int i = 0; i < msgBytes.length; i++) {
      if (offset == t.length) nextT();
      msgBytes[i] ^= t[offset++] & 0xFF;
    }
    final c2 = SMUtils.bytesToHexString(msgBytes);

    final c3 = SM3.hashBytes([...x2, ...utf8.encode(msg), ...y2]);
    return cipherMode == C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2;
  }

  /// 解密
  static String decrypt(String cipher, String privateKey,
      {int cipherMode = C1C3C2}) {
    final c1Hex = cipher.substring(0, 130); // 包含04前缀
    String c2Hex, c3Hex;

    if (cipherMode == C1C3C2) {
      c3Hex = cipher.substring(130, 130 + 64);
      c2Hex = cipher.substring(130 + 64);
    } else {
      c2Hex = cipher.substring(130, cipher.length - 64);
      c3Hex = cipher.substring(cipher.length - 64);
    }

    final c1Point = _ecParam.curve.decodePointHex(c1Hex)!;
    final priv = BigInt.parse(privateKey, radix: 16);
    final p = c1Point.multiply(priv);

    final x2 = SMUtils.hexStringToBytes(
        leftPad(p.getX().toBigInteger().toRadixString(16), 64));
    final y2 = SMUtils.hexStringToBytes(
        leftPad(p.getY().toBigInteger().toRadixString(16), 64));

    // KDF
    final c2Bytes = SMUtils.hexStringToBytes(c2Hex);
    int ct = 1;
    int offset = 0;
    List<int> t = [];
    final z = [...x2, ...y2];
    void nextT() {
      t = SMUtils.hexStringToBytes(SM3.hashBytes([
        ...z,
        (ct >> 24) & 0xFF,
        (ct >> 16) & 0xFF,
        (ct >> 8) & 0xFF,
        ct & 0xFF
      ]));
      ct++;
      offset = 0;
    }

    nextT();
    for (int i = 0; i < c2Bytes.length; i++) {
      if (offset == t.length) nextT();
      c2Bytes[i] ^= t[offset++] & 0xFF;
    }
    final checkC3 = SM3.hashBytes([...x2, ...c2Bytes, ...y2]);
    if (checkC3.toLowerCase() != c3Hex.toLowerCase()) return '';
    return utf8.decode(c2Bytes);
  }

  /// 计算 Z||M 的 SM3 哈希
  static String _getHash(String msg, String publicKey, String userId) {
    final uidHex = SMUtils.utf8ToHexString(userId);
    final a = leftPad(_ecParam.curve.a.toBigInteger().toRadixString(16), 64);
    final b = leftPad(_ecParam.curve.b.toBigInteger().toRadixString(16), 64);
    final gx = leftPad(_ecParam.G!.getX().toBigInteger().toRadixString(16), 64);
    final gy = leftPad(_ecParam.G!.getY().toBigInteger().toRadixString(16), 64);

    String px, py;
    if (publicKey.startsWith('04')) {
      px = publicKey.substring(2, 66);
      py = publicKey.substring(66, 130);
    } else {
      final pt = _ecParam.curve.decodePointHex(publicKey)!;
      px = leftPad(pt.getX().toBigInteger().toRadixString(16), 64);
      py = leftPad(pt.getY().toBigInteger().toRadixString(16), 64);
    }

    final entl = userId.length * 8; // bit数
    final zData = [
      (entl >> 8) & 0xFF,
      entl & 0xFF,
      ...SMUtils.hexStringToBytes(uidHex + a + b + gx + gy + px + py)
    ];
    final z = SMUtils.hexStringToBytes(SM3.hashBytes(zData));
    return SM3.hashBytes([...z, ...utf8.encode(msg)]);
  }

  static String _getPublicKeyFromPrivateKey(String privateKey) {
    final d = BigInt.parse(privateKey, radix: 16);
    final P = _ecParam.G!.multiply(d);
    final x = leftPad(P.getX().toBigInteger().toRadixString(16), 64);
    final y = leftPad(P.getY().toBigInteger().toRadixString(16), 64);
    return '04$x$y';
  }

  static KeyPair generateKeyPair() {
    final d = _randomK();
    final privateKeyHex = d.toRadixString(16).padLeft(64, '0');

    final P = _ecParam.G!.multiply(d);
    final xHex = leftPad(P.getX().toBigInteger().toRadixString(16), 64);
    final yHex = leftPad(P.getY().toBigInteger().toRadixString(16), 64);
    final publicKeyHex = '04$xHex$yHex';

    return KeyPair(privateKey: privateKeyHex, publicKey: publicKeyHex);
  }

}

class KeyPair {
  final String privateKey;
  final String publicKey;
  BigInt? k;
  BigInt? x1;

  KeyPair({required this.privateKey, required this.publicKey, this.k, this.x1});
}

class _EcParam {
  final ECCurveFp curve;
  final ECPointFp? G;
  final BigInt n;

  _EcParam({required this.curve, required this.G, required this.n});
}


