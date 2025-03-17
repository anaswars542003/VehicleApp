import asn1tools

asn1_schema = """
CertificateBase DEFINITIONS ::= BEGIN

Uint8 ::= INTEGER (0..255)
Uint32 ::= INTEGER (0..4294967295)
Uint16 ::= INTEGER (0..65535)
Time32 ::= Uint32

CertificateBase ::= SEQUENCE {
  version Uint8,
  tobeSignedData ToBeSignedCertificate,
  signature Signature
}

ToBeSignedCertificate ::= SEQUENCE {
  id OCTET STRING (SIZE(32)),
  validity Validity,
  anonymousPK OCTET STRING  (SIZE(128))
}

Validity ::= SEQUENCE {
  end Time32
}

Signature ::= CHOICE {
  ecdsaNistP256Signature  EcdsaP256Signature 
}

EcdsaP256Signature ::= SEQUENCE {
  rSig EccP256CurvePoint,
  sSig OCTET STRING (SIZE (32))
}

EccP256CurvePoint ::= SEQUENCE {
  x OCTET STRING (SIZE (32))
}

END
"""

# Compile ASN.1 schema for OER
asn1_compiled = asn1tools.compile_string(asn1_schema, 'oer')

# Example hex-encoded certificate (Replace with your actual data)
example_encoded_hex = bytes.fromhex("03964576AF51A9D0218D9A43DB0786276B1849A3CFA4346E2DB939EE081007365567D73526768400EA2CB413A1721CB97D6E4DEF90BF3C8366FDA5BBD8E9EBB25198FFCE2E8C018BCC39D82F307F9A52227F52B8B85598766806ABC3E7314DC7F44CE8FC60291AA848A004E91A9DBBEB9E36D9489F9F9368B2D56F09FFBFAD27B3667763EC958B0BBE61D6BC367C2F7C800A32A7A925ACE998D4C43F64BB0B2B0091E2AE7710D0C334F919973D369DAE9405CA97DEF87198DDF9B46C25448D410EBDB144505BA4876936FA1AC269A6584CC3AE1EEF3BEF080A6E581E4102C8FB99978889813D")

# Decode the certificate
decoded_certificate = asn1_compiled.decode('CertificateBase', example_encoded_hex)

# Print the decoded certificate
print(decoded_certificate)
