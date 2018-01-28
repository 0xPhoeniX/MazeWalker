#pragma once


namespace MazeWalker {

	class MemoryArea;
	class Image;

	// Factory method for creating memory areas
	class IMemoryAreaMaker {
	public:
		virtual MemoryArea* Create(int entry, int base, size_t size) const = 0;
		virtual ~IMemoryAreaMaker() {}
	};

	// Factory method for creating Image objects
	class IImageMaker {
	public:
		virtual Image* Create(int entry, int base, size_t size, const char* path) const = 0;
		virtual ~IImageMaker() {}
	};
}