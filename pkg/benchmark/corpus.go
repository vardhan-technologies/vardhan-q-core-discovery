package benchmark

// SeededCorpus contains ground-truth cryptographic cases (positives and negative decoys)
// across Go, Python, Java, and JavaScript/TypeScript.
var SeededCorpus = []BenchmarkCase{
	// ==================== GO CASES ====================
	{
		ID:          "go-tp-rsa-keygen",
		Language:    "go",
		CodeSnippet: "key, err := rsa.GenerateKey(rand.Reader, 2048)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
		NegativeAssertions: []string{"ECDSA", "DSA"},
	},
	{
		ID:          "go-tp-rsa-sign",
		Language:    "go",
		CodeSnippet: "sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, digest, nil)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
	},
	{
		ID:          "go-tp-ecdsa-keygen",
		Language:    "go",
		CodeSnippet: "key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECDSA"},
		},
		NegativeAssertions: []string{"RSA", "DSA"},
	},
	{
		ID:          "go-tp-ecdh-p256",
		Language:    "go",
		CodeSnippet: "curve := ecdh.P256()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECDH"},
		},
	},
	{
		ID:          "go-tp-dsa-keygen",
		Language:    "go",
		CodeSnippet: "err := dsa.GenerateKey(&privKey, rand.Reader)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "DSA"},
		},
		NegativeAssertions: []string{"ECDSA", "RSA"},
	},
	{
		ID:          "go-tp-md5-new",
		Language:    "go",
		CodeSnippet: "hasher := md5.New()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "MD5"},
		},
	},
	{
		ID:          "go-tp-sha1-new",
		Language:    "go",
		CodeSnippet: "h := sha1.New()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "SHA-1"},
		},
	},
	{
		ID:          "go-tp-3des-cipher",
		Language:    "go",
		CodeSnippet: "block, err := des.NewTripleDESCipher(key)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "3DES"},
		},
	},
	{
		ID:          "go-tp-rc4-cipher",
		Language:    "go",
		CodeSnippet: "cipher, err := rc4.NewCipher(key)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RC4"},
		},
	},
	{
		ID:          "go-tp-pqc-mlkem",
		Language:    "go",
		CodeSnippet: "kem := mlkem.New768()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ML-KEM"},
		},
	},
	{
		ID:          "go-tp-pqc-mldsa",
		Language:    "go",
		CodeSnippet: "sig := mldsa.New65()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ML-DSA"},
		},
	},
	{
		ID:          "go-tp-pqc-hybrid-x25519mlkem",
		Language:    "go",
		CodeSnippet: "tlsConfig.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "X25519MLKEM768"},
		},
	},
	// Go Negative Decoys (Must NOT trigger crypto rules)
	{
		ID:                 "go-decoy-variable-name",
		Language:           "go",
		CodeSnippet:        "var rsaKeyDescription = \"legacy key storage in vault\"",
		ExpectedMatches:    nil,
		NegativeAssertions: []string{"RSA", "ECDSA", "DSA"},
	},
	{
		ID:                 "go-decoy-noncrypto-sign",
		Language:           "go",
		CodeSnippet:        "approved := contract.Sign(signerEmployeeID)",
		ExpectedMatches:    nil,
		NegativeAssertions: []string{"RSA", "ECDSA", "DSA"},
	},

	// ==================== PYTHON CASES ====================
	{
		ID:          "py-tp-rsa-keygen",
		Language:    "python",
		CodeSnippet: "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
		NegativeAssertions: []string{"ECDSA"},
	},
	{
		ID:          "py-tp-ec-keygen",
		Language:    "python",
		CodeSnippet: "private_key = ec.generate_private_key(ec.SECP256R1())",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECDSA"},
		},
		NegativeAssertions: []string{"RSA"},
	},
	{
		ID:          "py-tp-dsa-keygen",
		Language:    "python",
		CodeSnippet: "private_key = dsa.generate_private_key(key_size=2048)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "DSA"},
		},
	},
	{
		ID:          "py-tp-md5",
		Language:    "python",
		CodeSnippet: "digest = hashlib.md5(data).hexdigest()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "MD5"},
		},
	},
	{
		ID:          "py-tp-sha1",
		Language:    "python",
		CodeSnippet: "h = hashlib.sha1(b'payload').hexdigest()",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "SHA-1"},
		},
	},
	{
		ID:          "py-tp-arc4",
		Language:    "python",
		CodeSnippet: "cipher = ARC4.new(key)",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "LegacyCipher"},
		},
	},
	{
		ID:          "py-tp-oqs-pqc",
		Language:    "python",
		CodeSnippet: "kem = oqs.KeyEncapsulation(\"ML-KEM-768\")",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "OQS-PQC"},
		},
	},
	// Python Decoy
	{
		ID:                 "py-decoy-comment",
		Language:           "python",
		CodeSnippet:        "# Note: We need to plan migration from RSA to ML-DSA next quarter",
		ExpectedMatches:    nil,
		NegativeAssertions: []string{"RSA", "DSA"},
	},

	// ==================== JAVA CASES ====================
	{
		ID:          "java-tp-rsa-kpg",
		Language:    "java",
		CodeSnippet: "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
		NegativeAssertions: []string{"ECDSA", "DSA"},
	},
	{
		ID:          "java-tp-rsa-cipher",
		Language:    "java",
		CodeSnippet: "Cipher cipher = Cipher.getInstance(\"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
	},
	{
		ID:          "java-tp-ec-kpg",
		Language:    "java",
		CodeSnippet: "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"EC\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECDSA"},
		},
		NegativeAssertions: []string{"RSA"},
	},
	{
		ID:          "java-tp-dsa-kpg",
		Language:    "java",
		CodeSnippet: "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"DSA\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "DSA"},
		},
	},
	{
		ID:          "java-tp-md5-digest",
		Language:    "java",
		CodeSnippet: "MessageDigest md = MessageDigest.getInstance(\"MD5\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "MD5"},
		},
	},
	{
		ID:          "java-tp-ecb-cipher",
		Language:    "java",
		CodeSnippet: "Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECB-Mode"},
		},
	},
	{
		ID:          "java-tp-pqc-bc",
		Language:    "java",
		CodeSnippet: "Security.addProvider(new BouncyCastlePQCProvider());",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "Java-PQC"},
		},
	},
	// Java Decoy
	{
		ID:                 "java-decoy-api-path",
		Language:           "java",
		CodeSnippet:        "String path = \"/api/v2/md5sum/lookup\";",
		ExpectedMatches:    nil,
		NegativeAssertions: []string{"MD5", "RSA"},
	},

	// ==================== JS / TS CASES ====================
	{
		ID:          "js-tp-rsa-keygen",
		Language:    "javascript",
		CodeSnippet: "crypto.generateKeyPairSync(\"rsa\", { modulusLength: 2048 });",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "RSA"},
		},
		NegativeAssertions: []string{"ECDSA"},
	},
	{
		ID:          "js-tp-ecdh",
		Language:    "javascript",
		CodeSnippet: "const ecdh = crypto.createECDH('secp256k1');",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "ECDH"},
		},
	},
	{
		ID:          "js-tp-md5-hash",
		Language:    "javascript",
		CodeSnippet: "const hash = crypto.createHash('md5').update('data').digest('hex');",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "MD5"},
		},
	},
	{
		ID:          "js-tp-sha1-hash",
		Language:    "javascript",
		CodeSnippet: "const hash = crypto.createHash('sha1').update('data').digest('hex');",
		ExpectedMatches: []ExpectedFinding{
			{Algorithm: "SHA-1"},
		},
	},
	// JS Decoy
	{
		ID:                 "js-decoy-object-property",
		Language:           "javascript",
		CodeSnippet:        "const authConfig = { algorithm: 'custom-oauth2', rsaSupported: false };",
		ExpectedMatches:    nil,
		NegativeAssertions: []string{"RSA", "ECDSA"},
	},
}
