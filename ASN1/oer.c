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
 * This file was generated by asn1tools version 0.167.0 Mon Apr  7 10:39:53 2025.
 */

#include <string.h>

#include "oer.h"

struct encoder_t {
    uint8_t *buf_p;
    ssize_t size;
    ssize_t pos;
};

struct decoder_t {
    const uint8_t *buf_p;
    ssize_t size;
    ssize_t pos;
};

static void encoder_init(struct encoder_t *self_p,
                         uint8_t *buf_p,
                         size_t size)
{
    self_p->buf_p = buf_p;
    self_p->size = (ssize_t)size;
    self_p->pos = 0;
}

static ssize_t encoder_get_result(const struct encoder_t *self_p)
{
    return (self_p->pos);
}

static void encoder_abort(struct encoder_t *self_p,
                          ssize_t error)
{
    if (self_p->size >= 0) {
        self_p->size = -error;
        self_p->pos = -error;
    }
}

static ssize_t encoder_alloc(struct encoder_t *self_p,
                             size_t size)
{
    ssize_t pos;

    if ((self_p->pos + (ssize_t)size) <= self_p->size) {
        pos = self_p->pos;
        self_p->pos += (ssize_t)size;
    } else {
        pos = -ENOMEM;
        encoder_abort(self_p, ENOMEM);
    }

    return (pos);
}

static void encoder_append_bytes(struct encoder_t *self_p,
                                 const uint8_t *buf_p,
                                 size_t size)
{
    ssize_t pos;

    pos = encoder_alloc(self_p, size);

    if (pos < 0) {
        return;
    }

    (void)memcpy(&self_p->buf_p[pos], buf_p, size);
}

static void encoder_append_uint8(struct encoder_t *self_p,
                                 uint8_t value)
{
    encoder_append_bytes(self_p, &value, sizeof(value));
}

static void encoder_append_uint16(struct encoder_t *self_p,
                                  uint16_t value)
{
    uint8_t buf[2];

    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)value;

    encoder_append_bytes(self_p, &buf[0], sizeof(buf));
}

static void encoder_append_uint32(struct encoder_t *self_p,
                                  uint32_t value)
{
    uint8_t buf[4];

    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;

    encoder_append_bytes(self_p, &buf[0], sizeof(buf));
}

static void encoder_append_uint(struct encoder_t *self_p,
                                uint32_t value,
                                uint8_t number_of_bytes)
{
    switch (number_of_bytes) {

    case 1:
        encoder_append_uint8(self_p, (uint8_t)value);
        break;

    case 2:
        encoder_append_uint16(self_p, (uint16_t)value);
        break;

    case 3:
        encoder_append_uint8(self_p, (uint8_t)(value >> 16));
        encoder_append_uint16(self_p, (uint16_t)value);
        break;

    default:
        encoder_append_uint32(self_p, value);
        break;
    }
}

static void decoder_init(struct decoder_t *self_p,
                         const uint8_t *buf_p,
                         size_t size)
{
    self_p->buf_p = buf_p;
    self_p->size = (ssize_t)size;
    self_p->pos = 0;
}

static ssize_t decoder_get_result(const struct decoder_t *self_p)
{
    return (self_p->pos);
}

static void decoder_abort(struct decoder_t *self_p,
                          ssize_t error)
{
    if (self_p->size >= 0) {
        self_p->size = -error;
        self_p->pos = -error;
    }
}

static ssize_t decoder_free(struct decoder_t *self_p,
                            size_t size)
{
    ssize_t pos;

    if ((self_p->pos + (ssize_t)size) <= self_p->size) {
        pos = self_p->pos;
        self_p->pos += (ssize_t)size;
    } else {
        pos = -EOUTOFDATA;
        decoder_abort(self_p, EOUTOFDATA);
    }

    return (pos);
}

static void decoder_read_bytes(struct decoder_t *self_p,
                               uint8_t *buf_p,
                               size_t size)
{
    ssize_t pos;

    pos = decoder_free(self_p, size);

    if (pos >= 0) {
        (void)memcpy(buf_p, &self_p->buf_p[pos], size);
    } else {
        (void)memset(buf_p, 0, size);
    }
}

static uint8_t decoder_read_uint8(struct decoder_t *self_p)
{
    uint8_t value;

    decoder_read_bytes(self_p, &value, sizeof(value));

    return (value);
}

static uint32_t decoder_read_uint32(struct decoder_t *self_p)
{
    uint8_t buf[4];

    decoder_read_bytes(self_p, &buf[0], sizeof(buf));

    return (((uint32_t)buf[0] << 24)
            | ((uint32_t)buf[1] << 16)
            | ((uint32_t)buf[2] << 8)
            | (uint32_t)buf[3]);
}

static uint32_t decoder_read_tag(struct decoder_t *self_p)
{
    uint32_t tag;

    tag = decoder_read_uint8(self_p);

    if ((tag & 0x3fu) == 0x3fu) {
        do {
            tag <<= 8;
            tag |= (uint32_t)decoder_read_uint8(self_p);
        } while ((tag & 0x80u) == 0x80u);
    }

    return (tag);
}

static void oer_send_data_signed_data_encode_inner(
    struct encoder_t *encoder_p,
    const struct oer_send_data_signed_data_t *src_p)
{
    encoder_append_bytes(encoder_p,
                         &src_p->data.buf[0],
                         120);
    encoder_append_uint32(encoder_p, src_p->timestamp);
    encoder_append_bytes(encoder_p,
                         &src_p->signer.buf[0],
                         32);
    encoder_append_bytes(encoder_p,
                         &src_p->signature.buf[0],
                         65);
}

static void oer_send_data_signed_data_decode_inner(
    struct decoder_t *decoder_p,
    struct oer_send_data_signed_data_t *dst_p)
{
    decoder_read_bytes(decoder_p,
                       &dst_p->data.buf[0],
                       120);
    dst_p->timestamp = decoder_read_uint32(decoder_p);
    decoder_read_bytes(decoder_p,
                       &dst_p->signer.buf[0],
                       32);
    decoder_read_bytes(decoder_p,
                       &dst_p->signature.buf[0],
                       65);
}

static void oer_send_data_content_encode_inner(
    struct encoder_t *encoder_p,
    const struct oer_send_data_content_t *src_p)
{
    switch (src_p->choice) {

    case oer_send_data_content_choice_signedData_e:
        encoder_append_uint(encoder_p, 0x10, 1);
        oer_send_data_signed_data_encode_inner(encoder_p, &src_p->value.signedData);
        break;

    case oer_send_data_content_choice_signedCertificateRequest_e:
        encoder_append_uint(encoder_p, 0x04, 1);
        encoder_append_bytes(encoder_p,
                             &src_p->value.signedCertificateRequest.buf[0],
                             32);
        break;

    default:
        encoder_abort(encoder_p, EBADCHOICE);
        break;
    }
}

static void oer_send_data_content_decode_inner(
    struct decoder_t *decoder_p,
    struct oer_send_data_content_t *dst_p)
{
    uint32_t tag;

    tag = decoder_read_tag(decoder_p);

    switch (tag) {

    case 0x10:
        dst_p->choice = oer_send_data_content_choice_signedData_e;
        oer_send_data_signed_data_decode_inner(decoder_p, &dst_p->value.signedData);
        break;

    case 0x04:
        dst_p->choice = oer_send_data_content_choice_signedCertificateRequest_e;
        decoder_read_bytes(decoder_p,
                           &dst_p->value.signedCertificateRequest.buf[0],
                           32);
        break;

    default:
        decoder_abort(decoder_p, EBADCHOICE);
        break;
    }
}

static void oer_send_data_send_data_encode_inner(
    struct encoder_t *encoder_p,
    const struct oer_send_data_send_data_t *src_p)
{
    encoder_append_uint8(encoder_p, src_p->protocolVersion);
    oer_send_data_content_encode_inner(encoder_p, &src_p->content);
}

static void oer_send_data_send_data_decode_inner(
    struct decoder_t *decoder_p,
    struct oer_send_data_send_data_t *dst_p)
{
    dst_p->protocolVersion = decoder_read_uint8(decoder_p);
    oer_send_data_content_decode_inner(decoder_p, &dst_p->content);
}

static void oer_send_data_timestamp_encode_inner(
    struct encoder_t *encoder_p,
    const struct oer_send_data_timestamp_t *src_p)
{
    encoder_append_uint32(encoder_p, src_p->value);
}

static void oer_send_data_timestamp_decode_inner(
    struct decoder_t *decoder_p,
    struct oer_send_data_timestamp_t *dst_p)
{
    dst_p->value = decoder_read_uint32(decoder_p);
}

static void oer_send_data_uint8_encode_inner(
    struct encoder_t *encoder_p,
    const struct oer_send_data_uint8_t *src_p)
{
    encoder_append_uint8(encoder_p, src_p->value);
}

static void oer_send_data_uint8_decode_inner(
    struct decoder_t *decoder_p,
    struct oer_send_data_uint8_t *dst_p)
{
    dst_p->value = decoder_read_uint8(decoder_p);
}

ssize_t oer_send_data_signed_data_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_send_data_signed_data_t *src_p)
{
    struct encoder_t encoder;

    encoder_init(&encoder, dst_p, size);
    oer_send_data_signed_data_encode_inner(&encoder, src_p);

    return (encoder_get_result(&encoder));
}

ssize_t oer_send_data_signed_data_decode(
    struct oer_send_data_signed_data_t *dst_p,
    const uint8_t *src_p,
    size_t size)
{
    struct decoder_t decoder;

    decoder_init(&decoder, src_p, size);
    oer_send_data_signed_data_decode_inner(&decoder, dst_p);

    return (decoder_get_result(&decoder));
}

ssize_t oer_send_data_content_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_send_data_content_t *src_p)
{
    struct encoder_t encoder;

    encoder_init(&encoder, dst_p, size);
    oer_send_data_content_encode_inner(&encoder, src_p);

    return (encoder_get_result(&encoder));
}

ssize_t oer_send_data_content_decode(
    struct oer_send_data_content_t *dst_p,
    const uint8_t *src_p,
    size_t size)
{
    struct decoder_t decoder;

    decoder_init(&decoder, src_p, size);
    oer_send_data_content_decode_inner(&decoder, dst_p);

    return (decoder_get_result(&decoder));
}

ssize_t oer_send_data_send_data_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_send_data_send_data_t *src_p)
{
    struct encoder_t encoder;

    encoder_init(&encoder, dst_p, size);
    oer_send_data_send_data_encode_inner(&encoder, src_p);

    return (encoder_get_result(&encoder));
}

ssize_t oer_send_data_send_data_decode(
    struct oer_send_data_send_data_t *dst_p,
    const uint8_t *src_p,
    size_t size)
{
    struct decoder_t decoder;

    decoder_init(&decoder, src_p, size);
    oer_send_data_send_data_decode_inner(&decoder, dst_p);

    return (decoder_get_result(&decoder));
}

ssize_t oer_send_data_timestamp_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_send_data_timestamp_t *src_p)
{
    struct encoder_t encoder;

    encoder_init(&encoder, dst_p, size);
    oer_send_data_timestamp_encode_inner(&encoder, src_p);

    return (encoder_get_result(&encoder));
}

ssize_t oer_send_data_timestamp_decode(
    struct oer_send_data_timestamp_t *dst_p,
    const uint8_t *src_p,
    size_t size)
{
    struct decoder_t decoder;

    decoder_init(&decoder, src_p, size);
    oer_send_data_timestamp_decode_inner(&decoder, dst_p);

    return (decoder_get_result(&decoder));
}

ssize_t oer_send_data_uint8_encode(
    uint8_t *dst_p,
    size_t size,
    const struct oer_send_data_uint8_t *src_p)
{
    struct encoder_t encoder;

    encoder_init(&encoder, dst_p, size);
    oer_send_data_uint8_encode_inner(&encoder, src_p);

    return (encoder_get_result(&encoder));
}

ssize_t oer_send_data_uint8_decode(
    struct oer_send_data_uint8_t *dst_p,
    const uint8_t *src_p,
    size_t size)
{
    struct decoder_t decoder;

    decoder_init(&decoder, src_p, size);
    oer_send_data_uint8_decode_inner(&decoder, dst_p);

    return (decoder_get_result(&decoder));
}
