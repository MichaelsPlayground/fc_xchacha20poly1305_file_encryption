# flutterconsoleempty

File encryption using XChacha20Poly1305 from flutter_sodium package

As the encryption and decryption run in chunks you can run the app

with very large files


```plaintext
convert: ^3.0.1
path_provider: ^2.0.7
pointycastle: ^3.4.0

sodium: 
https://pub.dev/packages/flutter_sodium
flutter_sodium: ^0.2.0
https://github.com/firstfloorsoftware/flutter_sodium
```

For building on MacOS Chip 1
ACHTUNG: in ISO/Podfile ergänzen und Podfile.lock löschen

```plaintext
post_install do |installer|
installer.pods_project.targets.each do |target|
flutter_additional_ios_build_settings(target)
# 兼容 Flutter 2.5
target.build_configurations.each do |config|
#       config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '9.0'
config.build_settings['EXCLUDED_ARCHS[sdk=iphonesimulator*]'] = 'i386 arm64'
end
end
end
```

Invalid argument(s): A directory corresponding to fileSystemPath "/Users/michaelfehr/.pub-cache/hosted/pub.dartlang.org/devtools-2.6.0/build" could not be found

/Users/michaelfehr/flutter pub cache repair

pub cache add devtools --version "0.1.15"


dart is in /Users/michaelfehr/flutter/bin/cache/dart-sdk

change module name:

Android Studio Project Tree

rechte Maustaste auf oberste Zeile, Refactor - Rename:

change package name:

use in flutter dev_dependencies:

change_app_package_name: ^1.0.0

run in terminal:

/Users/michaelfehr/flutter/bin/flutter pub run change_app_package_name:main de.fluttercrypto.fc_xchacha20poly1305_file_encryption

A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://flutter.dev/docs/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://flutter.dev/docs/cookbook)

For help getting started with Flutter, view our
[online documentation](https://flutter.dev/docs), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
