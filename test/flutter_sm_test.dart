import 'package:flutter_test/flutter_test.dart';
import 'package:gm_crypto/sm/sm2.dart';
import 'package:gm_crypto/sm/sm3.dart';
import 'package:gm_crypto/sm/sm4.dart';

void main() {
  group('SM2', () {
    test('generateKeyPair should return valid keypair', () {
      final keyPair = SM2.generateKeyPair();
      expect(keyPair.privateKey, isNotEmpty);
      expect(keyPair.publicKey, isNotEmpty);
    });

    test('signature and verify should work', () {
      final keyPair = SM2.generateKeyPair();
      const msg = 'Hello SM2!';
      final signature = SM2.signature(msg, keyPair.privateKey);
      final isValid = SM2.verifySignature(msg, signature, keyPair.publicKey);
      expect(isValid, true);
    });

    test('encrypt and decrypt should work', () {
      final keyPair = SM2.generateKeyPair();
      const msg = 'Hello SM2!';
      final cipher = SM2.encrypt(msg, keyPair.publicKey);
      final decrypted = SM2.decrypt(cipher, keyPair.privateKey);
      expect(decrypted, msg);
    });
  });

  group('SM3', () {
    test('hash should return 64 character hex string', () {
      const msg = 'Hello SM3!';
      final hash = SM3.hash(msg);
      expect(hash.length, 64);
    });

    test('same input should produce same hash', () {
      const msg = 'Hello SM3!';
      final hash1 = SM3.hash(msg);
      final hash2 = SM3.hash(msg);
      expect(hash1, hash2);
    });
  });

  group('SM4', () {
    test('ECB encrypt and decrypt should work', () {
      const plainText = 'Hello SM4!';
      const key = '0123456789abcdef0123456789abcdef';
      final cipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.ECB);
      final decrypted = SM4.decrypt(cipher, key: key, mode: SM4CryptoMode.ECB);
      expect(decrypted, plainText);
    });

    test('CBC encrypt and decrypt should work', () {
      const plainText = 'Hello SM4!';
      const key = '0123456789abcdef0123456789abcdef';
      const iv = 'fedcba9876543210fedcba9876543210';
      final cipher = SM4.encrypt(plainText, key: key, mode: SM4CryptoMode.CBC, iv: iv);
      final decrypted = SM4.decrypt(cipher, key: key, mode: SM4CryptoMode.CBC, iv: iv);
      expect(decrypted, plainText);
    });
  });
}
