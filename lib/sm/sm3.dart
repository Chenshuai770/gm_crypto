import 'dart:convert';

class SM3 {
  static const int _iv0 = 0x7380166F;
  static const int _iv1 = 0x4914B2B9;
  static const int _iv2 = 0x172442D7;
  static const int _iv3 = 0xDA8A0600;
  static const int _iv4 = 0xA96F30BC;
  static const int _iv5 = 0x163138AA;
  static const int _iv6 = 0xE38DEE4D;
  static const int _iv7 = 0xB0FB0E4E;

  static int _rotl(int x, int n) {
    // 防止负数移位，保证 n 在 0~31
    int s = (n % 32 + 32) % 32;
    x = x & 0xFFFFFFFF;
    return (((x << s) & 0xFFFFFFFF) | ((x >> (32 - s)) & 0xFFFFFFFF));
  }

  static int _ff(int x, int y, int z, int j) {
    if (j >= 0 && j <= 15) {
      return (x ^ y ^ z);
    } else {
      return ((x & y) | (x & z) | (y & z));
    }
  }

  static int _gg(int x, int y, int z, int j) {
    if (j >= 0 && j <= 15) {
      return (x ^ y ^ z);
    } else {
      return ((x & y) | (~x & z));
    }
  }

  static int _p0(int x) {
    return (x ^ _rotl(x, 9) ^ _rotl(x, 17));
  }

  static int _p1(int x) {
    return (x ^ _rotl(x, 15) ^ _rotl(x, 23));
  }

  static List<int> _padding(List<int> bytes) {
    int len = bytes.length * 8;
    bytes = List<int>.from(bytes)..add(0x80);
    while ((bytes.length % 64) != 56) {
      bytes.add(0x00);
    }
    // 添加长度（8字节，大端）
    for (int i = 7; i >= 0; i--) {
      bytes.add((len >> (i * 8)) & 0xFF);
    }
    return bytes;
  }

  static String hash(String msg) {
    return hashBytes(utf8.encode(msg));
  }

  static String hashBytes(List<int> input) {
    List<int> m = _padding(input);
    int n = m.length ~/ 64;

    List<int> v = [
      _iv0, _iv1, _iv2, _iv3, _iv4, _iv5, _iv6, _iv7
    ];

    for (int i = 0; i < n; i++) {
      List<int> b = m.sublist(i * 64, (i + 1) * 64);
      v = _cf(v, b);
    }

    // 输出
    StringBuffer sb = StringBuffer();
    for (var val in v) {
      sb.write(val.toRadixString(16).padLeft(8, '0'));
    }
    return sb.toString();
  }

  static List<int> hashBytesToBytes(List<int> input) {
    List<int> m = _padding(input);
    int n = m.length ~/ 64;

    List<int> v = [
      _iv0, _iv1, _iv2, _iv3, _iv4, _iv5, _iv6, _iv7
    ];

    for (int i = 0; i < n; i++) {
      List<int> b = m.sublist(i * 64, (i + 1) * 64);
      v = _cf(v, b);
    }

    // 输出字节数组
    List<int> out = [];
    for (var val in v) {
      out.addAll([
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 8) & 0xFF,
        val & 0xFF
      ]);
    }
    return out;
  }

  static List<int> _cf(List<int> v, List<int> b) {
    // 字数据 W
    List<int> w = List<int>.filled(68, 0);
    List<int> w1 = List<int>.filled(64, 0);
    for (int i = 0; i < 16; i++) {
      w[i] = ((b[4 * i] & 0xFF) << 24) |
      ((b[4 * i + 1] & 0xFF) << 16) |
      ((b[4 * i + 2] & 0xFF) << 8) |
      ((b[4 * i + 3] & 0xFF));
    }
    for (int i = 16; i < 68; i++) {
      w[i] = _p1(w[i - 16] ^ w[i - 9] ^ _rotl(w[i - 3], 15)) ^
      _rotl(w[i - 13], 7) ^
      w[i - 6];
    }
    for (int i = 0; i < 64; i++) {
      w1[i] = w[i] ^ w[i + 4];
    }

    // 压缩
    int a = v[0], b1 = v[1], c = v[2], d = v[3];
    int e = v[4], f = v[5], g = v[6], h = v[7];

    for (int j = 0; j < 64; j++) {
      int tj = (j >= 0 && j <= 15)
          ? 0x79CC4519
          : 0x7A879D8A;
      tj = _rotl(tj, j);

      int ss1 = _rotl(
          ((_rotl(a, 12) + e + tj) & 0xFFFFFFFF),
          7);
      int ss2 = ss1 ^ _rotl(a, 12);
      int tt1 = (_ff(a, b1, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF;
      int tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF;
      d = c;
      c = _rotl(b1, 9);
      b1 = a;
      a = tt1;
      h = g;
      g = _rotl(f, 19);
      f = e;
      e = _p0(tt2);
    }

    return [
      a ^ v[0],
      b1 ^ v[1],
      c ^ v[2],
      d ^ v[3],
      e ^ v[4],
      f ^ v[5],
      g ^ v[6],
      h ^ v[7]
    ];
  }
}
