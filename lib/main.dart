import 'dart:io';

import 'package:convert/convert.dart';
import 'package:flutter/material.dart';
import 'package:flutter/src/widgets/framework.dart' as flFramework;
import 'package:flutter/src/widgets/basic.dart' as flPadding;
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:path_provider/path_provider.dart';

import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_sodium/flutter_sodium.dart';


/* in pubspec.yaml eintragen:

 */

void main() => runApp(MyApp());
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter',
      home: Scaffold(
        appBar: AppBar(
          title: Text('Flutter Console'),
        ),
        body: MyWidget(),
      ),
    );
  }
}

// widget class
class MyWidget extends StatefulWidget {
  @override
  _MyWidgetState createState() => _MyWidgetState();
}

class _MyWidgetState extends flFramework.State<MyWidget> {
  // state variable
  String _textString = 'press the button "run the code"';
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Text(
          'console output',
          style: TextStyle(fontSize: 30),
        ),
        Expanded(
          flex: 1,
          child: new SingleChildScrollView(
            scrollDirection: Axis.vertical,
            child: flPadding.Padding(
                padding: EdgeInsets.fromLTRB(10, 5, 10, 5),
                child: Text(_textString,
                    style: TextStyle(
                      fontSize: 20.0,
                      fontWeight: FontWeight.bold,
                      fontFamily: 'Courier',
                      color: Colors.black,

                    ))),
          ),
        ),
        Container(
          child: Row(
            children: <Widget>[
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('clear console'),
                  onPressed: () {
                    clearConsole();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('extra Button'),
                  onPressed: () {
                    runYourSecondDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  child: Text('run the code'),
                  onPressed: () async {
                    runYourMainDartCode();
                  },
                ),
              ),
              SizedBox(width: 10),
            ],
          ),
        ),
      ],
    );
  }

  void clearConsole() {
    setState(() {
      _textString = ''; // will add additional lines
    });
  }

  void printC(_newString) {
    setState(() {
      _textString =
          _textString + _newString + '\n';
    });
    // additional printing to console
    print(_newString);
  }
  /* ### instructions ###
      place your code inside runYourMainDartCode and print it to the console
      using printC('your output to the console');
      clearConsole() clears the actual console
      place your code that needs to be executed additionally inside
      runYourSecondDartCode and start it with "extra Button"
   */
  Future<String> runYourMainDartCode() async  {
    printC('XChacha20 large file encryption SODIUM');

    Sodium.init();
    List listFiles = List.empty(growable: true);

    Directory directory = await getApplicationDocumentsDirectory();
    final String sourceFilePath = '${directory.path}/source_c.txt';
    final String cipherIvPbkdf2FilePath =
        '${directory.path}/cipher_iv_pbkdf2_c.txt';
    final String cipherIvArgon2FilePath =
        '${directory.path}/cipher_iv_argon2_c.txt';
    final String cipherIvFilePath = '${directory.path}/cipher_iv_c.txt';
    final String cipherNewFilePath = '${directory.path}/cipher_new_c.txt';
    final String cipherOldFilePath = '${directory.path}/cipher_old_c.txt';
    final String decryptOldFilePath = '${directory.path}/decrypt_old_c.txt';
    final String decryptIvPbkdf2FilePath =
        '${directory.path}/decrypt_iv_pbkdf2_c.txt';
    final String decryptIvArgon2FilePath =
        '${directory.path}/decrypt_iv_argon2_c.txt';
    final String decryptIvFilePath = '${directory.path}/decrypt_iv_c.txt';
    final String decryptNewFilePath = '${directory.path}/decrypt_new_c.txt';

    // fixed key and iv - this is just for testing purposes
    String keyString = '12345678123456781234567812345678'; // 32 chars
    //String nonceString = '76543210'; // 8 chars
    Uint8List key = createUint8ListFromString(keyString);
    //Uint8List nonce = createUint8ListFromString(nonceString);
    if (_fileExistsSync(sourceFilePath)) {
      _deleteFileSync(sourceFilePath);
    }

    // generate a 'large' file with random content
    //final int testDataLength = (1024 * 1024); // 1 mb
    final int testDataLength = (1024 * 7 + 0);
    final step1 = Stopwatch()..start();
    Uint8List randomData = _generateRandomByte(testDataLength);
    _generateLargeFileSync(sourceFilePath, randomData, 1);
    //_generateLargeFileSync(sourceFilePath, randomData, 50);

    var step1Elapsed = step1.elapsed;

    printC('\ndata for reference');
    // for reference
    // get sha-256 of file
    Uint8List sourceSha256 = await _getSha256File(sourceFilePath);
    int sourceFileLength = await _getFileLength(sourceFilePath);
    printC('sourcePath fileLength: ' + sourceFileLength.toString());
    printC('sourcePath SHA-256:     ' + bytesToHex(sourceSha256));
    // encrypt in one run
    final step2 = Stopwatch()..start();
    Uint8List plaintextLoad = _readUint8ListSync(sourceFilePath);
    //printC('content source: ' + bytesToHex(plaintextLoad));
    //Uint8List ciphertextOld = Uint8List(1);
    /* out of memory 50 mb */
    EncryptionResult encResultCiphertextOld = await _encryptXChacha20Poly1305MemorySodium(plaintextLoad, key);
    _writeUint8ListSync(cipherOldFilePath, encResultCiphertextOld.encryptedData);
    var step2Elapsed = step2.elapsed;
    Uint8List cipherOldSha256 = await _getSha256File(cipherOldFilePath);
    int cipherOldFileLength = await _getFileLength(cipherOldFilePath);
    printC('cipherOldPath fileLength: ' + cipherOldFileLength.toString());
    printC('cipherOldPath SHA-256:  ' + bytesToHex(cipherOldSha256));
    // decrypt in one run
    final step3 = Stopwatch()..start();
    Uint8List ciphertextOldLoad = await _readUint8ListSync(cipherOldFilePath);
    //Uint8List decrypttextOld = Uint8List(1);
    /* out of memory error 50 mb*/
    Uint8List decrypttextOld = await _decryptXChacha20Poly1305MemorySodium(ciphertextOldLoad, key, encResultCiphertextOld.header);
    _writeUint8ListSync(decryptOldFilePath, decrypttextOld);
    var step3Elapsed = step3.elapsed;
    Uint8List decryptOldSha256 = await _getSha256File(decryptOldFilePath);
    int decryptOldFileLength = await _getFileLength(decryptOldFilePath);
    printC('decryptOldPath fileLength: ' + decryptOldFileLength.toString());
    printC('decryptOldPath SHA-256: ' + bytesToHex(decryptOldSha256));

    // delete new file if exist
    //_deleteFileSync(cipherNewFilePath);
    //printC('\nfile ' + cipherNewFilePath + ' deleted if existed');

    printC('\ndata encryption using SODIUM');
    // important: delete destinationFile before encryption
    if (_fileExistsSync(cipherNewFilePath)) _deleteFileSync(cipherNewFilePath);
    //printC('\nfile ' + cipherNewFilePath + ' deleted if existed');

    // now encryption using chunks
    final step4 = Stopwatch()..start();
    Uint8List encHeader = await _encryptXChacha20Poly1305Sodium(
        sourceFilePath, cipherNewFilePath, key);
    var step4Elapsed = step4.elapsed;
    // check the data
    Uint8List cipherNewSha256S = await _getSha256File(cipherNewFilePath);
    int cipherNewFileLengthS = await _getFileLength(cipherNewFilePath);
    printC('cipherNewPath fileLength: ' + cipherNewFileLengthS.toString());
    printC('cipherNewPath SHA-256:  ' + bytesToHex(cipherNewSha256S));
    //Uint8List cipherNewS = _readUint8ListSync(cipherNewFilePath);

    // now decryption using chunks
    printC('\ndata decryption using Sodium');
    // important: delete destinationFile before encryption
    if (_fileExistsSync(decryptNewFilePath)) _deleteFileSync(decryptNewFilePath);
    final step5 = Stopwatch()..start();
    // get nonce from header
    var nonceSodiumHeader = encHeader;
    printC('SODIUM header nonce: ' + bytesToHex(nonceSodiumHeader));

    await _decryptXChacha20Poly1305Sodium(
        cipherNewFilePath, decryptNewFilePath, key, nonceSodiumHeader);
    var step5Elapsed = step5.elapsed;
    // check the data
    Uint8List decryptNewSha256S = await _getSha256File(decryptNewFilePath);
    int decryptNewFileLengthS = await _getFileLength(decryptNewFilePath);
    printC('decryptNewPath fileLength: ' + decryptNewFileLengthS.toString());
    printC('decryptNewPath SHA-256:  ' + bytesToHex(decryptNewSha256S));

    printC(
        '\ndata encryption using RAF and chunks with random iv stored in file SODIUM');

    // important: delete destinationFile before encryption
    if (_fileExistsSync(cipherIvFilePath)) _deleteFileSync(cipherIvFilePath);

    // now encryption using chunks
    final step6 = Stopwatch()..start();
    //await _encryptChacha20RandomNonce(sourceFilePath, cipherIvFilePath, key);
    await _encryptXChacha20Poly1305RandomNonceSodium(sourceFilePath, cipherIvFilePath, key);
    var step6Elapsed = step6.elapsed;
    // check the data
    Uint8List cipherIvSha256 = await _getSha256File(cipherIvFilePath);
    int cipherIvFileLength = await _getFileLength(cipherIvFilePath);
    printC('cipherIvPath fileLength: ' + cipherIvFileLength.toString());
    printC('cipherIvPath SHA-256:   ' + bytesToHex(cipherIvSha256));

    // now decryption using chunks
    printC(
        '\ndata decryption using RAF and chunks with random iv stored in file');

    // important: delete destinationFile before encryption
    if (_fileExistsSync(decryptIvFilePath)) _deleteFileSync(decryptIvFilePath);

    final step7 = Stopwatch()..start();
    await _decryptXChacha20Poly1305RandomNonceSodium(cipherIvFilePath, decryptIvFilePath, key);
    var step7Elapsed = step7.elapsed;
    // check the data
    Uint8List decryptIvSha256 = await _getSha256File(decryptIvFilePath);
    int decryptIvFileLength = await _getFileLength(decryptIvFilePath);
    printC('decryptIvPath fileLength: ' + decryptIvFileLength.toString());
    printC('decryptIvPath SHA-256:   ' + bytesToHex(decryptIvSha256));

    printC(
        '\ndata encryption using RAF and chunks with random iv stored in file and PBKDF2 key derivation');
    // now encryption using chunks
    // important: delete destinationFile before encryption
    if (_fileExistsSync(cipherIvPbkdf2FilePath)) _deleteFileSync(cipherIvPbkdf2FilePath);
    String password = 'secret password';
    final step8 = Stopwatch()..start();
    await _encryptXChacha20Poly1305RandomNoncePbkdf2Sodium(
        sourceFilePath, cipherIvPbkdf2FilePath, password);
    var step8Elapsed = step8.elapsed;
    // check the data
    Uint8List cipherIvPbkdf2Sha256 =
    await _getSha256File(cipherIvPbkdf2FilePath);
    int cipherIvPbkdf2FileLength = await _getFileLength(cipherIvPbkdf2FilePath);
    printC('cipherIvPbkdf2Path fileLength: ' +
        cipherIvPbkdf2FileLength.toString());
    printC('cipherIvPbkdf2Path SHA-256:   ' + bytesToHex(cipherIvPbkdf2Sha256));

    // now decryption using chunks
    printC(
        '\ndata decryption using RAF and chunks with random iv stored in file and PBKDF2 key derivation');
    // important: delete destinationFile before encryption
    if (_fileExistsSync(decryptIvPbkdf2FilePath)) _deleteFileSync(decryptIvPbkdf2FilePath);
    final step9 = Stopwatch()..start();
    await _decryptXChacha20Poly1305RandomNoncePbkdf2Sodium(
        cipherIvPbkdf2FilePath, decryptIvPbkdf2FilePath, password);
    var step9Elapsed = step9.elapsed;
    // check the data
    Uint8List decryptIvPbkdf2Sha256 =
    await _getSha256File(decryptIvPbkdf2FilePath);
    int decryptIvPbkdf2FileLength =
    await _getFileLength(decryptIvPbkdf2FilePath);
    printC('decryptIvPbkdf2Path fileLength: ' +
        decryptIvPbkdf2FileLength.toString());
    printC(
        'decryptIvPbkdf2Path SHA-256:   ' + bytesToHex(decryptIvPbkdf2Sha256));

    printC(
        '\ndata encryption using RAF and chunks with random iv stored in file and Argon2ID key derivation');
    // now encryption using chunks
    // important: delete destinationFile before encryption
    if (_fileExistsSync(cipherIvArgon2FilePath)) _deleteFileSync(cipherIvArgon2FilePath);
    String passwordArgon = 'secret password';
    final step10 = Stopwatch()..start();
    await _encryptXChacha20Poly1305RandomNonceArgon2Sodium(
        sourceFilePath, cipherIvArgon2FilePath, passwordArgon);
    var step10Elapsed = step10.elapsed;
    // check the data
    Uint8List cipherIvArgon2Sha256 =
    await _getSha256File(cipherIvArgon2FilePath);
    int cipherIvArgon2FileLength = await _getFileLength(cipherIvArgon2FilePath);
    printC('cipherIvArgon2Path fileLength: ' +
        cipherIvArgon2FileLength.toString());
    printC('cipherIvArgon2Path SHA-256:   ' + bytesToHex(cipherIvArgon2Sha256));

    // now decryption using chunks
    printC(
        '\ndata decryption using RAF and chunks with random iv stored in file and Argon2 key derivation');
    // important: delete destinationFile before decryption
    if (_fileExistsSync(decryptIvArgon2FilePath)) _deleteFileSync(decryptIvArgon2FilePath);
    final step11 = Stopwatch()..start();
    await _decryptXChacha20Poly1305RandomNonceArgon2Sodium(
        cipherIvArgon2FilePath, decryptIvArgon2FilePath, passwordArgon);
    var step11Elapsed = step11.elapsed;
    // check the data
    Uint8List decryptIvArgon2Sha256 =
    await _getSha256File(decryptIvArgon2FilePath);
    int decryptIvArgon2FileLength =
    await _getFileLength(decryptIvArgon2FilePath);
    printC('decryptIvArgon2Path fileLength: ' +
        decryptIvArgon2FileLength.toString());
    printC(
        'decryptIvArgon2Path SHA-256:   ' + bytesToHex(decryptIvArgon2Sha256));

    // print out all again
    printC('');
    printC('*********** benchmark all steps ************');

    printC('step 1 generate data:       ' +
        step1Elapsed.inMicroseconds.toString());
    //printC('testDataLength:             ' + testDataLength.toString() + ' bytes');
    printC('step 2 encrypt in memory:   ' +
        step2Elapsed.inMicroseconds.toString());
    printC('step 3 decrypt in memory:   ' +
        step3Elapsed.inMicroseconds.toString());
    printC('step 4 encrypt chunked:     ' +
        step4Elapsed.inMicroseconds.toString());
    printC('step 5 decrypt chunked:     ' +
        step5Elapsed.inMicroseconds.toString());
    printC('step 6 encrypt chunked iv:  ' +
        step6Elapsed.inMicroseconds.toString());
    printC('step 7 decrypt chunked iv:  ' +
        step7Elapsed.inMicroseconds.toString());
    printC('step 8 encrypt chu PBKDF2:  ' +
        step8Elapsed.inMicroseconds.toString());
    printC('step 9 decrypt chu PBKDF2:  ' +
        step9Elapsed.inMicroseconds.toString());
    printC('step 10 encrypt chu Argon2: ' +
        step10Elapsed.inMicroseconds.toString());
    printC('step 11 decrypt chu Argon2: ' +
        step11Elapsed.inMicroseconds.toString());
    // get list of files
    printC('alle Dateien:\n');
    listFiles = await _getFiles();
    for (var i = 0; i < listFiles.length; i++) {
      printC(listFiles[i].toString());
    }
    //clearConsole();
    
  return '';
  }

  void runYourSecondDartCode() {
    printC('execute additional code');
  }

  Future<void> _encryptXChacha20Poly1305RandomNonceArgon2Sodium(String sourceFilePath, String destinationFilePath, String password) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize = encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;

    // argon2 key derivation
    var passphrase =  createUint8ListFromString(password);
    final int saltLength = 16;
    final salt = Sodium.randombytesBuf(saltLength);
    final outlen = 32;
    final opslimit = Sodium.cryptoPwhashOpslimitSensitive;
    final memlimit = Sodium.cryptoPwhashMemlimitInteractive;
    final alg = Sodium.cryptoPwhashAlgArgon2id13;
    final key =
    Sodium.cryptoPwhash(outlen, passphrase, salt, opslimit, memlimit, alg);
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    final sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    final initPushResult =
    Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    // write salt and nonce to file
    await destinationFile.writeAsBytes(salt, mode: FileMode.append);
    await destinationFile.writeAsBytes(initPushResult.header, mode: FileMode.append);

    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        tag = Sodium.cryptoSecretstreamXchacha20poly1305TagFinal;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final encryptedData = Sodium.cryptoSecretstreamXchacha20poly1305Push(
          initPushResult.state, buffer, null, tag);
      await destinationFile.writeAsBytes(encryptedData, mode: FileMode.append);
    }
    inputFile.closeSync();
    return;
  }

  Future<void> _decryptXChacha20Poly1305RandomNonceArgon2Sodium(String sourceFilePath, String destinationFilePath, String password) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize =
        encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final int nonceLength = Sodium.cryptoSecretstreamXchacha20poly1305Headerbytes;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    int sourceFileLength = await sourceFile.length();
    print("Decrypting file of size " + sourceFileLength.toString());
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    // get salt and nonce from file
    final int saltLength = 16; // salt for argon2
    final salt = inputFile.readSync(saltLength);
    final nonce = inputFile.readSync(nonceLength);

    // argon2 key derivation
    var passphrase =  createUint8ListFromString(password);
    final outlen = 32;
    final opslimit = Sodium.cryptoPwhashOpslimitSensitive;
    final memlimit = Sodium.cryptoPwhashMemlimitInteractive;
    final alg = Sodium.cryptoPwhashAlgArgon2id13;
    final key =
    Sodium.cryptoPwhash(outlen, passphrase, salt, opslimit, memlimit, alg);
    final pullState = Sodium.cryptoSecretstreamXchacha20poly1305InitPull(nonce, key);
    var bytesRead = 0;
    // correct sourceFileLength for saltLength and nonceLength
    sourceFileLength = sourceFileLength - saltLength - nonceLength;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = decryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final pullResult =
      Sodium.cryptoSecretstreamXchacha20poly1305Pull(pullState, buffer, null);
      await destinationFile.writeAsBytes(pullResult.m, mode: FileMode.append);
      tag = pullResult.tag;
    }
    inputFile.closeSync();
  }

  Future<void> _encryptXChacha20Poly1305RandomNoncePbkdf2Sodium(String sourceFilePath, String destinationFilePath, String password) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize = encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;

    // pbkdf2 key derivation
    // sodium lib does not provide pbkdf2, using pointycastle for this task
    final int saltLength = 32; // salt for pbkdf2
    final int PBKDF2_ITERATIONS = 15000;
    // derive key from password
    var passphrase =  createUint8ListFromString(password);
    final salt = _generateRandomByte(saltLength);
    // generate and store salt in destination file
    pc.KeyDerivator derivator = new pc.PBKDF2KeyDerivator(new pc.HMac(new pc.SHA256Digest(), 64));
    pc.Pbkdf2Parameters params = new pc.Pbkdf2Parameters(salt, PBKDF2_ITERATIONS, 32);
    derivator.init(params);
    final key = derivator.process(passphrase);

    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    final sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    final initPushResult =
    Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    // write salt and nonce to file
    await destinationFile.writeAsBytes(salt, mode: FileMode.append);
    await destinationFile.writeAsBytes(initPushResult.header, mode: FileMode.append);

    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        tag = Sodium.cryptoSecretstreamXchacha20poly1305TagFinal;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final encryptedData = Sodium.cryptoSecretstreamXchacha20poly1305Push(
          initPushResult.state, buffer, null, tag);
      await destinationFile.writeAsBytes(encryptedData, mode: FileMode.append);
    }
    inputFile.closeSync();
    return;
  }

  Future<void> _decryptXChacha20Poly1305RandomNoncePbkdf2Sodium(String sourceFilePath, String destinationFilePath, String password) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize =
        encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final int nonceLength = Sodium.cryptoSecretstreamXchacha20poly1305Headerbytes;
    final decryptionStartTime = DateTime.now().millisecondsSinceEpoch;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    int sourceFileLength = await sourceFile.length();
    print("Decrypting file of size " + sourceFileLength.toString());
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    // get salt and nonce from file
    final int saltLength = 32; // salt for pbkdf2
    final salt = inputFile.readSync(saltLength);
    final nonce = inputFile.readSync(nonceLength);
    // pbkdf2 key derivation
    // sodium lib does not provide pbkdf2, using pointycastle for this task
    final int PBKDF2_ITERATIONS = 15000;
    // derive key from password
    var passphrase =  createUint8ListFromString(password);
    // generate and store salt in destination file
    pc.KeyDerivator derivator = new pc.PBKDF2KeyDerivator(new pc.HMac(new pc.SHA256Digest(), 64));
    pc.Pbkdf2Parameters params = new pc.Pbkdf2Parameters(salt, PBKDF2_ITERATIONS, 32);
    derivator.init(params);
    final key = derivator.process(passphrase);
    final pullState = Sodium.cryptoSecretstreamXchacha20poly1305InitPull(nonce, key);
    var bytesRead = 0;
    // correct sourceFileLength for saltLength and nonceLength
    sourceFileLength = sourceFileLength - saltLength - nonceLength;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = decryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final pullResult =
      Sodium.cryptoSecretstreamXchacha20poly1305Pull(pullState, buffer, null);
      await destinationFile.writeAsBytes(pullResult.m, mode: FileMode.append);
      tag = pullResult.tag;
    }
    inputFile.closeSync();
  }

  Future<void> _encryptXChacha20Poly1305RandomNonceSodium(String sourceFilePath, String destinationFilePath, Uint8List key) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize = encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    final sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    final initPushResult =
    Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    await destinationFile.writeAsBytes(initPushResult.header, mode: FileMode.append);

    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        tag = Sodium.cryptoSecretstreamXchacha20poly1305TagFinal;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final encryptedData = Sodium.cryptoSecretstreamXchacha20poly1305Push(
          initPushResult.state, buffer, null, tag);
      await destinationFile.writeAsBytes(encryptedData, mode: FileMode.append);
    }
    inputFile.closeSync();
    return;
  }

  Future<void> _decryptXChacha20Poly1305RandomNonceSodium(String sourceFilePath, String destinationFilePath, Uint8List key) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize =
        encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final int nonceLength = Sodium.cryptoSecretstreamXchacha20poly1305Headerbytes;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    int sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    // get nonce from file
    final nonce = inputFile.readSync(nonceLength);
    final pullState = Sodium.cryptoSecretstreamXchacha20poly1305InitPull(nonce, key);

    // correct sourceFileLength for nonceLength
    sourceFileLength = sourceFileLength - nonceLength;

    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = decryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final pullResult =
      Sodium.cryptoSecretstreamXchacha20poly1305Pull(pullState, buffer, null);
      await destinationFile.writeAsBytes(pullResult.m, mode: FileMode.append);
      tag = pullResult.tag;
    }
    inputFile.closeSync();
  }

  Future<Uint8List> _encryptXChacha20Poly1305Sodium(String sourceFilePath, String destinationFilePath, Uint8List key) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize = encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    final sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    final initPushResult =
    Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = encryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
        tag = Sodium.cryptoSecretstreamXchacha20poly1305TagFinal;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final encryptedData = Sodium.cryptoSecretstreamXchacha20poly1305Push(
          initPushResult.state, buffer, null, tag);
      await destinationFile.writeAsBytes(encryptedData, mode: FileMode.append);
    }
    inputFile.closeSync();
    return initPushResult.header;
  }

  Future<void> _decryptXChacha20Poly1305Sodium(String sourceFilePath, String destinationFilePath, Uint8List key, Uint8List nonce) async {
    //final int encryptionChunkSize = 4 * 1024 * 1024; // 4 mb
    final int encryptionChunkSize = 2048;
    final int decryptionChunkSize =
        encryptionChunkSize + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
    final sourceFile = File(sourceFilePath);
    final destinationFile = File(destinationFilePath);
    final sourceFileLength = await sourceFile.length();
    final inputFile = sourceFile.openSync(mode: FileMode.read);
    final pullState = Sodium.cryptoSecretstreamXchacha20poly1305InitPull(nonce, key);

    var bytesRead = 0;
    var tag = Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
    while (tag != Sodium.cryptoSecretstreamXchacha20poly1305TagFinal) {
      var chunkSize = decryptionChunkSize;
      if (bytesRead + chunkSize >= sourceFileLength) {
        chunkSize = sourceFileLength - bytesRead;
      }
      final buffer = inputFile.readSync(chunkSize);
      bytesRead += chunkSize;
      final pullResult =
      Sodium.cryptoSecretstreamXchacha20poly1305Pull(pullState, buffer, null);
      await destinationFile.writeAsBytes(pullResult.m, mode: FileMode.append);
      tag = pullResult.tag;
    }
    inputFile.closeSync();
  }

  Future<EncryptionResult> _encryptXChacha20Poly1305MemorySodium(Uint8List sourceData, Uint8List key) async {
    final initPushResult =
    Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    final encryptedData = Sodium.cryptoSecretstreamXchacha20poly1305Push(
        initPushResult.state,
        sourceData,
        null,
        Sodium.cryptoSecretstreamXchacha20poly1305TagFinal);
    return EncryptionResult(encryptedData: encryptedData, header: initPushResult.header, key: Uint8List(0), nonce: Uint8List(0));
  }

  Future<Uint8List> _decryptXChacha20Poly1305MemorySodium(Uint8List sourceData, Uint8List key, Uint8List header) async {
    final pullState = Sodium.cryptoSecretstreamXchacha20poly1305InitPull(header, key);
    final pullResult = Sodium.cryptoSecretstreamXchacha20poly1305Pull(
        pullState, sourceData, null);
    return pullResult.m;
  }

  Uint8List _generateRandomByte(int length) {
    final _sGen = Random.secure();
    final _seed =
    Uint8List.fromList(List.generate(32, (n) => _sGen.nextInt(255)));
    pc.SecureRandom sec = pc.SecureRandom("Fortuna")
      ..seed(pc.KeyParameter(_seed));
    return sec.nextBytes(length);
  }

  Future<int> _getFileLength(String path) async {
    File file = File(path);
    RandomAccessFile raf = await file.open(mode: FileMode.read);
    int fileLength = await raf.length();
    raf.close();
    return fileLength;
  }

  Future<Uint8List> _getSha256File(String path) async {
    File file = File(path);
    RandomAccessFile raf = await file.open(mode: FileMode.read);
    int fileLength = await raf.length();
    await raf.setPosition(0); // from position 0
    Uint8List fileConent = await raf.read(fileLength); // reading all bytes
    raf.close();
    return await calculateSha256FromUint8List(fileConent);
  }

  Future<Uint8List> calculateSha256FromUint8List(Uint8List dataToDigest) async {
    var d = pc.Digest('SHA-256');
    return await d.process(dataToDigest);
  }

  String bytesToHex(Uint8List data) {
    return hex.encode(data);
  }

  _deleteFileSync(String path) {
    File file = File(path);
    file.deleteSync();
  }

  Uint8List createUint8ListFromString(String s) {
    var ret = new Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }



  bool _fileExistsSync(String path) {
    File file = File(path);
    return file.existsSync();
  }

  // reading from a file
  Uint8List _readUint8ListSync(String path) {
    File file = File(path);
    return file.readAsBytesSync();
  }

  // writing to a file
  _writeUint8ListSync(String path, Uint8List data) {
    File file = File(path);
    file.writeAsBytesSync(data);
  }

  // writing to a file
  _writeUint8List(String path, Uint8List data) async {
    File file = File(path);
    await file.writeAsBytes(data);
  }

  // generate a large testfile with random data
  _generateLargeFileSync(String path, Uint8List data, int numberWrite) {
    File file = File(path);
    for (int i = 0; i < numberWrite; i++) {
      file.writeAsBytesSync(data, mode: FileMode.writeOnlyAppend);
    }
  }

  Future<List> _getFiles() async {
    //String folderName="MyFiles";
    String folderName = '';
    final directory = await getApplicationDocumentsDirectory();
    final Directory _appDocDirFolder =
    Directory('${directory.path}/${folderName}/');
    if (await _appDocDirFolder.exists()) {
      //if folder already exists return path
      return _appDocDirFolder.listSync();
    }
    return List.empty(growable: true);
  }



}

class EncryptionResult {
  final Uint8List encryptedData;
  final Uint8List key;
  final Uint8List header;
  final Uint8List nonce;

  EncryptionResult({required this.encryptedData, required this.key, required this.header, required this.nonce});
}

