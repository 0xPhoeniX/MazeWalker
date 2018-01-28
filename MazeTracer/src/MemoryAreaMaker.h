#pragma once
#include "IMemoryAreaMaker.h"
#include "MemoryTracer.h"


namespace MazeWalker {
	template<typename T>
	class MemoryAreaMaker: public IMemoryAreaMaker {
	public:

		MemoryAreaMaker() {
			MemoryTracer::Instance().RegisterMemoryAreaType(this);
		}

		virtual MemoryArea* Create(int entry, int base, size_t size) const {
			if (T::isValid((char*)base, size)) {
				return new T(entry, base, size);
			}
			return NULL;
		}
	};

	template<typename T>
	class ImageMaker: public IImageMaker {
	public:

		ImageMaker() {
			MemoryTracer::Instance().RegisterImageType(this);
		}

		virtual Image* Create(int entry, int base, size_t size, const char* path) const {
			if (T::isValid((char*)base, size)) {
				return new T(entry, base, size, path);
			}
			return NULL;
		}
	};
}