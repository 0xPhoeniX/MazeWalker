#pragma once
#include "IMemoryAreaMaker.h"
#include "MemoryArea.h"
#include "Image.h"


namespace MazeWalker {

	// Singleton class for managing all memory areas during tracing
	class MemoryTracer {
	public:
		static MemoryTracer& Instance();
		void RegisterMemoryAreaType(IMemoryAreaMaker* maker);
		void RegisterImageType(IImageMaker* maker);

		// Returns Memory area object by the address confined in it's areas.
		// If such object does not exist, it will be created and added into
		// internal cache.
		MemoryArea* getMemoryArea(int address);

		// Create Image object from DBI framework's internal object (e.g. Pin's IMG)
		// PIN is the only supported right now, but the idea is to support at least
		// DynamoRIO too.
		Image* CreateImage(void* imgObj);
	private:
		MemoryTracer();
		MemoryTracer(const MemoryTracer& other);
		MemoryTracer& operator=(const MemoryTracer& other);

		void* _blob_reg;
		void* _mas;
		void* _img_reg;
	};
}