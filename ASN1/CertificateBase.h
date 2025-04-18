/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2019 Erik Moqvist
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * This file was generated by asn1tools version 0.167.0 Mon Mar 17 21:54:15 2025.
 */

#ifndef CERTIFICATEBASE_H
#define CERTIFICATEBASE_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#ifndef ENOMEM
#    define ENOMEM 12
#endif

#ifndef EINVAL
#    define EINVAL 22
#endif

#ifndef EOUTOFDATA
#    define EOUTOFDATA 500
#endif

#ifndef EBADCHOICE
#    define EBADCHOICE 501
#endif

#ifndef EBADLENGTH
#    define EBADLENGTH 502
#endif

#ifndef EBADENUM
#    define EBADENUM 503
#endif

/**
 * Type Validity in module CertificateBase.
 */
struct oer_certificate_base_validity_t {
    uint32_t end;
};

/**
 * Type ToBeSignedCertificate in module CertificateBase.
 */
struct oer_certificate_base_to_be_signed_certificate_t {
    struct {
        uint8_t buf[32];
    } id;
    struct oer_certificate_base_validity_t validity;
    struct {
        uint8_t buf[128];
    } anonymousPK;
};

/**
 * Type EccP256CurvePoint in module CertificateBase.
 */
struct oer_certificate_base_ecc_p256_curve_point_t {
    struct {
        uint8_t buf[32];
    } x;
};

/**
 * Type EcdsaP256Signature in module CertificateBase.
 */
struct oer_certificate_base_ecdsa_p256_signature_t {
    struct oer_certificate_base_ecc_p256_curve_point_t rSig;
    struct {
        uint8_t buf[32];
    } sSig;
};

/**
 * Type Signature in module CertificateBase.
 */
enum oer_certificate_base_signature_choice_e {
    oer_certificate_base_signature_choice_ecdsaNistP256Signature_e
};

struct oer_certificate_base_signature_t {
    enum oer_certificate_base_signature_choice_e choice;
    union {
        struct oer_certificate_base_ecdsa_p256_signature_t ecdsaNistP256Signature;
    } value;
};

/**
 * Type CertificateBase in module CertificateBase.
 */
struct oer_certificate_base_certificate_base_t {
    uint8_t version;
    struct oer_certificate_base_to_be_signed_certificate_t tobeSignedData;
    struct oer_certificate_base_signature_t signature;
};

/**
 * Type Time32 in module CertificateBase.
 */
struct oer_certificate_base_time32_t {
    uint32_t value;
};

/**
 * Type Uint16 in module CertificateBase.
 */
struct oer_certificate_base_uint16_t {
    uint16_t value;
};

/**
 * Type Uint32 in module CertificateBase.
 */
struct oer_certificate_base_uint32_t {
    uint32_t value;
};

/**
 * Type Uint8 in module CertificateBase.
 */
struct oer_certificate_base_uint8_t {
    uint8_t value;
};

/**
 * Encode type Validity defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_validity_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_validity_t *src_p);

/**
 * Decode type Validity defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_validity_decode(
    struct oer_certificate_base_validity_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type ToBeSignedCertificate defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_to_be_signed_certificate_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_to_be_signed_certificate_t *src_p);

/**
 * Decode type ToBeSignedCertificate defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_to_be_signed_certificate_decode(
    struct oer_certificate_base_to_be_signed_certificate_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type EccP256CurvePoint defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_ecc_p256_curve_point_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_ecc_p256_curve_point_t *src_p);

/**
 * Decode type EccP256CurvePoint defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_ecc_p256_curve_point_decode(
    struct oer_certificate_base_ecc_p256_curve_point_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type EcdsaP256Signature defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_ecdsa_p256_signature_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_ecdsa_p256_signature_t *src_p);

/**
 * Decode type EcdsaP256Signature defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_ecdsa_p256_signature_decode(
    struct oer_certificate_base_ecdsa_p256_signature_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type Signature defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_signature_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_signature_t *src_p);

/**
 * Decode type Signature defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_signature_decode(
    struct oer_certificate_base_signature_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type CertificateBase defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_certificate_base_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_certificate_base_t *src_p);

/**
 * Decode type CertificateBase defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_certificate_base_decode(
    struct oer_certificate_base_certificate_base_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type Time32 defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_time32_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_time32_t *src_p);

/**
 * Decode type Time32 defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_time32_decode(
    struct oer_certificate_base_time32_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type Uint16 defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_uint16_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_uint16_t *src_p);

/**
 * Decode type Uint16 defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_uint16_decode(
    struct oer_certificate_base_uint16_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type Uint32 defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_uint32_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_uint32_t *src_p);

/**
 * Decode type Uint32 defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_uint32_decode(
    struct oer_certificate_base_uint32_t *dst_p,
    const uint8_t *src_p,
    size_t size);

/**
 * Encode type Uint8 defined in module CertificateBase.
 *
 * @param[out] dst_p Buffer to encode into.
 * @param[in] size Size of dst_p.
 * @param[in] src_p Data to encode.
 *
 * @return Encoded data length or negative error code.
 */
ssize_t oer_certificate_base_uint8_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_certificate_base_uint8_t *src_p);

/**
 * Decode type Uint8 defined in module CertificateBase.
 *
 * @param[out] dst_p Decoded data.
 * @param[in] src_p Data to decode.
 * @param[in] size Size of src_p.
 *
 * @return Number of bytes decoded or negative error code.
 */
ssize_t oer_certificate_base_uint8_decode(
    struct oer_certificate_base_uint8_t *dst_p,
    const uint8_t *src_p,
    size_t size);

#endif
