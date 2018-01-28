#pragma once
#include "MemoryArea.h"


namespace MazeWalker {

    // The abstract class for arbitrary in-memory loaded image.
	class Image : public MemoryArea {
	public:
		Image(int entry, int base, size_t size) : MemoryArea(entry, base, size) {}
		virtual ~Image() {}

		// Resolve address into a symbol if present in Image.
		virtual const char* Resolve(int address) const = 0;

		// Returns image name.
		virtual const char* Name() const = 0;

		// Returns image on-disk storage path, if present.
		virtual const char* Path() const = 0;

		// Calculates and returns hash for all import functions (imphash).
		virtual const char* ImpHash() const = 0;

		// Calculates and returns hash for all exported functions.
		// The same idea as for the imphash.
		virtual const char* ExpHash() const = 0;
	};
}