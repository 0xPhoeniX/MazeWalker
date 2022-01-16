#ifndef _MAZEWALKER_CRYPTO_H_
#define _MAZEWALKER_CRYPTO_H_

namespace MazeWalker {
	// calculate md5 hash for a given buffer
	//		buf - data buffer
	//		size - size of the buffer
	//		md5 - calculated hash value
	int calc_buf_md5(const char* buf, size_t size, char* md5);

}

#endif
