import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:flutter_sm/flutter_sm.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('SM2 integration test', (WidgetTester tester) async {
    final keyPair = SM2.generateKeyPair();
    expect(keyPair.privateKey, isNotEmpty);
    expect(keyPair.publicKey, isNotEmpty);
  });

  testWidgets('SM3 integration test', (WidgetTester tester) async {
    final hash = SM3.hash('test');
    expect(hash.length, 64);
  });

  testWidgets('SM4 integration test', (WidgetTester tester) async {
    const key = '0123456789abcdef0123456789abcdef';
    final cipher = SM4.encrypt('test', key: key);
    final decrypted = SM4.decrypt(cipher, key: key);
    expect(decrypted, 'test');
  });
}
