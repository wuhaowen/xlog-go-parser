package main

import (
	"io/ioutil"
	"encoding/binary"
	"bytes"
	"errors"
	"fmt"
	"compress/zlib"
	"io"
)

const MAGIC_NO_COMPRESS_START = 0x03
const MAGIC_NO_COMPRESS_START1 = 0x06
const MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08
const MAGIC_COMPRESS_START = 0x04
const MAGIC_COMPRESS_START1 = 0x05
const MAGIC_COMPRESS_START2 = 0x07
const MAGIC_COMPRESS_NO_CRYPT_START = 0x09

const MAGIC_END = 0x00

var lastseq = 0

func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp uint32
	binary.Read(bytesBuffer, binary.LittleEndian, &tmp)
	return int(tmp)
}

func BytesToShort(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp uint16
	binary.Read(bytesBuffer, binary.LittleEndian, &tmp)
	return int(tmp)
}

func IsGoodLogBuffer(_buffer []byte, _offset int, count int) (bool, error) {
	if _offset == len(_buffer) {
		return true, nil
	}
	magic_start := _buffer[_offset]
	crypt_key_len := 0
	if MAGIC_NO_COMPRESS_START == magic_start || MAGIC_COMPRESS_START == magic_start || MAGIC_COMPRESS_START1 == magic_start {
		crypt_key_len = 4
	} else if MAGIC_COMPRESS_START2 == magic_start || MAGIC_NO_COMPRESS_START1 == magic_start || MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start || MAGIC_COMPRESS_NO_CRYPT_START == magic_start {
		crypt_key_len = 64
	} else {
		return false, errors.New("_buffer[" + string(_offset) + "]:" + string(_buffer[_offset]) + " != MAGIC_NUM_START")
	}
	headerLen := 1 + 2 + 1 + 1 + 4 + crypt_key_len

	if _offset+headerLen+1+1 > len(_buffer) {
		return false, errors.New(fmt.Sprintf("'offset:%d > len(buffer):%d", _offset, len(_buffer)))
	}
	s := _buffer[ _offset+headerLen-4-crypt_key_len:  _offset+headerLen-crypt_key_len]
	length := BytesToInt(s)

	if _offset+headerLen+length+1 > len(_buffer) {
		return false, errors.New(fmt.Sprintf("log length:%d, end pos %d > len(buffer):%d", length, _offset+headerLen+length+1, len(_buffer)))

	}
	if MAGIC_END != _buffer[_offset+headerLen+length] {
		return false, errors.New(fmt.Sprintf("log length:%d, buffer[%d]:%d != MAGIC_END", length, _offset+headerLen+length, _buffer[_offset+headerLen+length]))
	}
	if 1 >= count {
		return true, nil
	}
	return IsGoodLogBuffer(_buffer, _offset+headerLen+length+1, count-1)
}

func GetLogStartPos(_buffer []byte, _count int) int {
	offset := 0
	for ; ; {
		if offset >= len(_buffer) {
			break
		}
		if MAGIC_NO_COMPRESS_START == _buffer[offset] || MAGIC_NO_COMPRESS_START1 == _buffer[offset] || MAGIC_COMPRESS_START == _buffer[offset] || MAGIC_COMPRESS_START1 == _buffer[offset] || MAGIC_COMPRESS_START2 == _buffer[offset] || MAGIC_COMPRESS_NO_CRYPT_START == _buffer[offset] || MAGIC_NO_COMPRESS_NO_CRYPT_START == _buffer[offset] {
			if isGood, _ := IsGoodLogBuffer(_buffer, offset, _count); isGood {
				return offset
			}
		}
		offset += 1
	}
	return -1
}

func DecodeBuffer(_buffer []byte, _offset int, _outbuffer *[]byte) int {

	if _offset >= len(_buffer) {
		return -1
	}
	ret, err := IsGoodLogBuffer(_buffer, _offset, 1)
	fixpos := 0
	if !ret {
		fixpos = GetLogStartPos(_buffer[_offset:], 1)
		if fixpos == -1 {
			return -1
		} else {
			//append(_outbuffer, )
			*_outbuffer = append(*_outbuffer, []byte(fmt.Sprintf("decode error len=%d, result:%s\n", fixpos, err.Error()))...)

			_offset += fixpos

		}
	}
	magic_start := _buffer[_offset]
	crypt_key_len := 0
	if MAGIC_NO_COMPRESS_START == magic_start || MAGIC_COMPRESS_START == magic_start || MAGIC_COMPRESS_START1 == magic_start {
		crypt_key_len = 4
	} else if MAGIC_COMPRESS_START2 == magic_start || MAGIC_NO_COMPRESS_START1 == magic_start || MAGIC_NO_COMPRESS_NO_CRYPT_START == magic_start || MAGIC_COMPRESS_NO_CRYPT_START == magic_start {
		crypt_key_len = 64
	} else {
		*_outbuffer = append(*_outbuffer, []byte(fmt.Sprintf("in DecodeBuffer _buffer[%d]:%d != MAGIC_NUM_START\n", fixpos, magic_start))...)

		return -1
	}
	headerLen := 1 + 2 + 1 + 1 + 4 + crypt_key_len
	length_buffer := _buffer[_offset+headerLen-4-crypt_key_len:_offset+headerLen-crypt_key_len]
	length := BytesToInt(length_buffer)
	seq_buffer := _buffer[ _offset+headerLen-4-crypt_key_len-2-2:   _offset+headerLen-4-crypt_key_len-2]
	seq := BytesToShort(seq_buffer)
	if seq != 0 && seq != 1 && lastseq != 0 && seq != lastseq+1 {
		*_outbuffer = append(*_outbuffer, []byte(fmt.Sprintf("log seq:%d-%d is missing\n", lastseq+1, seq-1))...)

	}

	if seq != 0 {
		lastseq = seq
	}
	tmpbuffer := _buffer[_offset+headerLen:_offset+headerLen+length]
	if MAGIC_NO_COMPRESS_START1 == _buffer[_offset] || MAGIC_COMPRESS_START2 == _buffer[_offset] {
		fmt.Println("use wrong decode script")
	} else if MAGIC_COMPRESS_START == _buffer[_offset] || MAGIC_COMPRESS_NO_CRYPT_START == _buffer[_offset] {
		tmpbuffer, err = DoZlibUnCompress(tmpbuffer)
	} else if MAGIC_COMPRESS_START1 == _buffer[_offset] {
		var decompress_data []byte
		for len(tmpbuffer) > 0 {
			single_log_len_buffer := tmpbuffer[0: 2]
			single_log_len := BytesToShort(single_log_len_buffer)
			decompress_data = append(decompress_data, tmpbuffer[2:single_log_len+2]...)
			tmpbuffer = tmpbuffer[single_log_len+2: ]
		}
		tmpbuffer, err = DoZlibUnCompress(decompress_data)
	}
	if err != nil {
		*_outbuffer = append(*_outbuffer, []byte("decompress err, "+err.Error()+"\n")...)
		return _offset + headerLen + length + 1
	}
	*_outbuffer = append(*_outbuffer, tmpbuffer...)
	return _offset + headerLen + length + 1

}

func DoZlibUnCompress(compressSrc []byte) ([]byte, error) {
	var i int16 = 0x78da
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(i))
	b = append(b, compressSrc...)
	source := bytes.NewReader(b)
	var out bytes.Buffer
	r, err := zlib.NewReader(source)
	if err != nil {
		return nil, err
	}
	io.Copy(&out, r)
	return out.Bytes(), nil
}

func ParseFile(_file string, _outFile string) {
	_buffer, err := ioutil.ReadFile(_file)
	if err != nil {
		panic(err)
	}
	startpos := GetLogStartPos(_buffer, 2)
	if -1 == startpos {
		return
	}
	var outbuffer []byte
	for startpos != -1 {
		startpos = DecodeBuffer(_buffer, startpos, &outbuffer)
	}
	if len(outbuffer) == 0 {
		return
	}

	ioutil.WriteFile(_outFile, outbuffer, 0644)

}

func main() {
	ParseFile("./1.xlog", "./2.log")
}
