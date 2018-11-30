#### AES
> PHP、iOS、Android 三端加解密
```php
<?php
// 默认 AES-128-CBC
$aes = Crypt::aes([
    'key' => Str::random(16),
]);
$encrypt = $aes->encrypt('test');
$decrypt = $aes->decrypt($encrypt);

// AES-256-CBC
$aes = Crypt::aes([
    'key' => Str::random(32),
    'cipher' => 'AES-256-CBC',
]);
$encrypt = $aes->encrypt('test');
$decrypt = $aes->decrypt($encrypt);
```

> 加解密(支持MAC校验, 防止时序攻击)
```php
<?php
// 默认 AES-128-CBC
$aes = Crypt::aes([
    'key' => Str::random(16),
]);
$encrypt = $aes->encryptWithMac('test');
$decrypt = $aes->decryptWithMac($encrypt);

// AES-256-CBC
$aes = Crypt::aes([
    'key' => Str::random(32),
    'cipher' => 'AES-256-CBC',
]);
$encrypt = $aes->encryptWithMac('test');
$decrypt = $aes->decryptWithMac($encrypt);
```

#### RSA
> 加解密
```php
<?php
// 加解密
$aes = Crypt::rsa([
    'publicKey' => __DIR__ . '/public.pem',
    'privateKey' => __DIR__ . '/private.pem',
]);
$encrypt = $aes->encrypt('test');
$decrypt = $aes->decrypt($encrypt);
```

> 生成签名及校验(拼接KEY)
```php
$aes = Crypt::rsa([
    'key' => Str::random(16),
]);
$data = [
    'type' => 1,
    'value' => 'test'
];
// 生成签名
$data['sign'] = $aes->generateSign($data);
// 校验签名
$verifyResult = $aes->verifySign($data);
```

> 生成签名及校验(RSA签名)
```php
$aes = Crypt::rsa([
    'publicKey' => 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1hgDgNvvAymqO7LLT8HY0yMdYP3y8Ms8SSSVFAzP2U5QNN+9r/L5J/Omxs5yXbY10NmjCkn6JfkOQTeNs+G+roNymsxf/S12yt0PmBblbjUGay1bWBH/Z44bZSnVRcPQYJ9tzKjI8LH6Hc3hKOE9Uk3JZ3xw0o1zbF9OhsuOCimV543FxovLsTZymbAvYOaeacpCT/lI6DRYaCE0yIn9FeUBcYnDl2uev+KGRM5YMclfwM1J+ow/6TQd9gF0i6Xd0RL1+9H4bjTl+MpySu2pFAlLlQI/KJl2xRDz2TFIxCRZvsMn3lJK4moGBQvyu7+bEM1mVAiu27r0qesK8JHjYwIDAQAB',
    'privateKey' => 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWGAOA2+8DKao7sstPwdjTIx1g/fLwyzxJJJUUDM/ZTlA0372v8vkn86bGznJdtjXQ2aMKSfol+Q5BN42z4b6ug3KazF/9LXbK3Q+YFuVuNQZrLVtYEf9njhtlKdVFw9Bgn23MqMjwsfodzeEo4T1STclnfHDSjXNsX06Gy44KKZXnjcXGi8uxNnKZsC9g5p5pykJP+UjoNFhoITTIif0V5QFxicOXa56/4oZEzlgxyV/AzUn6jD/pNB32AXSLpd3REvX70fhuNOX4ynJK7akUCUuVAj8omXbFEPPZMUjEJFm+wyfeUkriagYFC/K7v5sQzWZUCK7buvSp6wrwkeNjAgMBAAECggEAFapIcHnRLhjBSVlGicOsFXGwP2hzdTqb1ysEiwrg3bS3GSKrJ2sHG6vkbKnnmOQffgsIHLpvvff+IUtl45YsnaxfpJqZ/BzlsJG+Sj3G6egjxiTI4Ziwp+IRk6MwGec+5wg7LELIUtMv5GQ5LNHeSr3ka7yEDkqSK51ZbPqcXRq41trQ/afCFIw6VjCgJyO0zPNiT22LytobRi55+biQpUbwHy/TTKztzQQ+dZo69IxdUwsrCVVJt7Ymr/229H7FBsmvCvRfV6O2qcB4E0BhnJSDkLkPIehqOasobzwhT4tuhGxzlth9Jpe3fWfp4nbFT937aui93yLGkwWtNFmhQQKBgQDqUZQRl5UnuOUAxs+0GiW1XXKB6cM+p0jC3EBAWIezvQM1+hdFxCRZJSVvPIPd8m/TV31/DNxQjlwR52/uOJtxUudgkc7d5e/V9zb0Wlvv0VV12rCJCB3+NilDL5SXWjPLAgCTHff/b/oK4GOjzrlnvGL1p6ED1tUN6sIgjaG8PwKBgQDp51vo+JWvidS66tlxZ1aHcLKRqTo9MPGGGFFapQaEuKC8t18/4/HyJtuHDr/NXQV7JB7ERREXTn8sPpJ95rza1K+HB64X6DC/MmalA7KUAyks6u6XIbwpHV2SnbOGCgbdzBX1R8LTW2XdTNNCe1u/lIUt7990XYAVdh4ZPylf3QKBgBQSdOqk34QNlKBiZ3x4GO7WWG7EhZMiZVs73s0kSEufT10aVVAGo053niNPPcSPdgDWp8twYJcN+tkVyELR2o70mRlupBfiEI91o+F+tA1xEy8LUsAKT/ds0FAPDV2BvpoPS9lOYeYhw3uXCTIJDVzTiG6es25OwuV0TLjZKRelAoGAGD6T50UE9un5c9pt6XRFospKqBB7aeZN0pFotVWPpGgiuQzkwZGV/XyLmqcruFShAc+PpNZn3BuV0Pc3ZfdpseEDxKJGKFI340mNHCOS+gaN2QsM6ftkLnrNvSm9dvJJHepOiFsE1bWOjG6vIx/4NZZma4mGhuA+K3tPyVwjpL0CgYEAhNB3iXIc04HqWwKuSac4aexiSJ1ozFU48FWiW0F/8Y+a0qkvLChhD1kNJ5wSr84KGkJGQPJbiclcJiAw9hD2LU6biJIUH/1luTzfFyMFDRLWc9WpeBKdtIfAsxX996VQl4x6cTGkgejWXRA4LBw0T2/coID3GqO4JHb5DAEaOQ4=',
]);
$data = [
    'type' => 1,
    'value' => 'test'
];
// 生成签名
$sign = $aes->generateSignWithOpenssl($data);
// 校验签名
$verifyResult = $aes->verifySignWithOpenssl($data, $sign);
```