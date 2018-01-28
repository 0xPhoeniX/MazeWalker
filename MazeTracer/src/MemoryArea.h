#pragma once
#include "IReportObject.h"
#include "Thread.h"


//#define REGISTER_MATYPE(T) static MazeWalker::MemoryAreaMaker<T> maker;
//#define REGISTER_DEFAULTMATYPE(T) static MazeWalker::DefaultMemoryAreaMaker<T> maker()

namespace MazeWalker {

	enum MemoryAreaStatus {
		Different,
		Equal,
		Error
	};

	// The class represents an arbitrary virtual memory area.
	// In case of code alternation as of decryption/replacement,
	// in the controlled ares, the new, authentic, state will be saved.
	class MemoryArea : public IReportObject {
	public:

		// ctor. 
		// entry: address of the first instruction to be executed.
		// base:  the base address for the memory area
		// size:  the size of the allocated memory chunk
		MemoryArea(int entry, int base, size_t size);
		virtual ~MemoryArea();

		// Save the contents of the memory area to a file. All states 
		// will be saved too, if present.
		//
		// path_prefix: full directory path to save the data to.
		//				The file name(s) will be generated internally.
		void Dump(const char* path_prefix);

		// Add thread object which is executing in the memory area.
		void addThread(Thread* thread);
		Thread* getThread(int id) const;

		// Check the difference status between latest saved data and 
		// current (online) patch.
		// 
		// address: starting address of the patch to check
		// size:    the size of the patch
		MemoryAreaStatus StatusAt(int address, int size) const;

		// Save current, existing, in-memory data The saved state will
		// become the new default state.
		//
		// entry:  the address of the execution entry in the saved state.
		// return: true on success and false otherwise.
		bool saveState(int entry);

		size_t Size() const { return _size; }
		int Base() const { return _base; }

		// Save object description to a json object.
		virtual bool toJson( Json::Value& root ) const;

	protected:
		// The method is internally called before any dump of the state 
		// occurs.
		//
		// data: data before the dump
		// size: size of the data
		virtual void processBeforeDump(char* data, size_t size) = 0;

		// This method must return file extension according to the 
		// memory area contents.
		//
		// return: file extension. The memory will not be freed after the use.
		virtual const char* getFileType() const = 0;

		const char* getLatestState(size_t& size) const;

		void* _states;
		int _base;
		size_t _size;
		static int _idGenerator;
	};
}