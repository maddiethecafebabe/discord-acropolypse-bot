# Adapted from https://github.com/infobyte/CVE-2023-21036
# Based on https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02

import zlib
from typing import Union


PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

class StubbedAssertException(Exception):
	pass

def stubbed_assert(cond):
	if not(cond):
		raise StubbedAssertException()

def parse_png_chunk(stream):
	size = int.from_bytes(stream.read(4), "big")
	ctype = stream.read(4)
	body = stream.read(size)
	csum = int.from_bytes(stream.read(4), "big")
	stubbed_assert(zlib.crc32(ctype + body) == csum)
	return ctype, body

def valid_png_iend(trailer):
	iend_pos = len(trailer) - 8
	iend_size = int.from_bytes(trailer[iend_pos-4:iend_pos], "big")
	iend_csum = int.from_bytes(trailer[iend_pos+4:iend_pos+8], "big")
	return iend_size == 0 and iend_csum == 0xAE426082

def parse_png(f_in):
	magic = f_in.read(len(PNG_MAGIC))
	stubbed_assert(magic == PNG_MAGIC)
	# find end of cropped PNG
	while True:
		ctype, body = parse_png_chunk(f_in)
		if ctype == b"IEND":
			break

	# grab the trailing data
	trailer = f_in.read()

	return trailer and valid_png_iend(trailer)

# true == vulnerable
def parse_jpeg(f_in) -> bool:
	SOI_marker = f_in.read(2)
	stubbed_assert(SOI_marker == b"\xFF\xD8")
	APP0_marker = f_in.read(2)
	stubbed_assert(APP0_marker == b"\xFF\xE0")
	APP0_size = int.from_bytes(f_in.read(2), "big")
	APP0_body = f_in.read(APP0_size - 2)
	stubbed_assert(APP0_body[:4] == b"JFIF")
	
	f_in.seek(0,0)
	file = f_in.read()
	EOI_marker_pos = file.index(b"\xFF\xD9")

	stubbed_assert(EOI_marker_pos)
	
	cropped = file[:EOI_marker_pos + 2]
	trailer = file[EOI_marker_pos + 2:]

	return trailer and trailer[-2:] == b"\xFF\xD9"

def test_picture_bytes(buf) -> Union[bool, None]:
	import io

	fp = io.BytesIO(buf)
	start = fp.read(2)
	fp.seek(0, 0)

	try:
		if start == b"\x89P":
			return parse_png(fp)
		elif start == b"\xFF\xD8":
			return parse_jpeg(fp)
		else:
			return None
	except StubbedAssertException:
		print("encountered invalid png/jpg, skipping..")
		return None

if __name__ == "__main__":
	import sys

	if len(sys.argv) != 2:
		print(f"USAGE: {sys.argv[0]} cropped.png/jpg")
		exit()

	fp = open(sys.argv[1], "rb")
	res = test_picture_bytes(fp.read())
	
	if res is None:
		print("doesn't seem to be a valid png/jpg file")
	else:
		print(f"{sys.argv[1]} seems to {['not be', 'be'][res]} vulnerable")
	