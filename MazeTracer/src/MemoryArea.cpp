#include "MemoryArea.h"
#include "WinAddress.h"
#include "cfg.h"
#include <cstdlib>
#include <string>
#include <sstream>
#include <list>
#include <set>
#include <ostream>
#include <vector>


#define THREAD_LIMIT 100

namespace MazeWalker {

	typedef struct _layer {
		char* data;
		size_t size;
		int entry;
		int id;
		std::vector<Thread*> threads;
	} LAYER, *PLAYER;

	class State {
	public:
		State(int base, size_t size, int entry) : _entry(entry), _size(size) {
			_data = new char[size];
			if (_data) {
				memset(_data, 0, _size);
				memcpy(_data, (void*)base, _size);
			}
			threads.reserve(THREAD_LIMIT);
			for (int i = 0; i < THREAD_LIMIT; i++) { threads[i] = 0; }
			_id = State::_idGenerator++;
			// LOG(string(__FUNCTION__) + ": Adding State: "+ hexstr(base) + " with id " + decstr(_id) + "\n");
		}

		~State() {
			if (_data) {
				delete [] _data;
				_data = 0;
			}

			for (int i = 0; i < THREAD_LIMIT; i++) { threads[i] = 0; }
			_size = _entry = _id = 0;
		}

		char* _data;
		size_t _size;
		int _entry;
		int _id;
		std::vector<Thread*> threads;
		static int _idGenerator;
	};

	int MemoryArea::_idGenerator = 0;

	MemoryArea::MemoryArea(int entry, int base, size_t size) {
		_base = _size = 0;
		_states = NULL;
		PLAYER l = NULL;

		_states = new std::list<PLAYER>;
		l = new LAYER;
		if (l && _states) {
			l->data = new char[size];
			if (l->data) {
				_base = base;
				l->size = _size = size;
				l->threads.reserve(THREAD_LIMIT);
				for (int i = 0; i < THREAD_LIMIT; i++) { l->threads[i] = 0; }
				l->entry = entry;
				l->id = MemoryArea::_idGenerator++;
				// LOG(string(__FUNCTION__) + ": Adding ma: "+ hexstr(base) + " with id " + decstr(l->id) + "\n");
				memset(l->data, 0, size);
				memcpy(l->data, (void*)base, size);
				((std::list<PLAYER>*)(_states))->push_back(l);
				return;
			}
		}
		delete _states;
		delete [] l->data;
		delete l;
	}

	MemoryArea::~MemoryArea() {
		std::list<PLAYER>::iterator iter;

		if (_states) {
			for (iter = ((std::list<PLAYER>*)(_states))->begin();
				 iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
					 delete [] (*iter)->data;
					 (*iter)->data = 0;
					 (*iter)->size = 0;
					 delete *iter;
					 *iter = 0;
			}
			((std::list<PLAYER>*)(_states))->clear();
			delete _states;
			_states = 0;
		}
	}

	bool MemoryArea::saveState(int entry) {
		PLAYER l;
		IAddress& addr = WinAddress(entry, true);

		if (_size > 0 && _base > 0 && _states) {
			if (addr.Base() == _base) {
				l = new LAYER;
				if (l) {
					l->data = new char[addr.Size()];
					if (l->data) {
						l->size = addr.Size();
						l->entry = entry;
						l->threads.reserve(THREAD_LIMIT);
						for (int i = 0; i < THREAD_LIMIT; i++) { l->threads[i] = 0; }
						l->id = MemoryArea::_idGenerator++;
						memcpy(l->data, (void*)addr.Base(), addr.Size());
						((std::list<PLAYER>*)(_states))->push_back(l);
						return true;
					}
					delete l;
					l = 0;
				}
			}
		}

		return false;
	}

	MemoryAreaStatus MemoryArea::StatusAt(int address, int size) const {
		int offset;
		std::list<PLAYER>::const_reverse_iterator iter;
		IAddress& addr = WinAddress(address);


		if (addr.Base() == _base) {
			if ((address + size) <= (addr.Base() + addr.Size())) {
				offset = address - _base;
				iter = ((std::list<PLAYER>*)(_states))->rbegin();
				if (iter != ((std::list<PLAYER>*)(_states))->rend()) {
					if ((address + size) <= (_base + (*iter)->size)) {
						if (memcmp((char*)((*iter)->data) + offset, (void*)address, size) != 0) {
							return Different;
						}
						else {
							return Equal;
						}
					}
				}
			}
		}

		return Error;
	}

	void MemoryArea::Dump(const char* path_prefix) {
		const char* ftype = getFileType();
		std::list<PLAYER>::const_iterator iter;
		FILE* dump;

		if (path_prefix && strlen(path_prefix) > 0) {
			for (iter = ((std::list<PLAYER>*)(_states))->begin();
				 iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
					 std::ostringstream fpath;

					 fpath << path_prefix << "_" << (*iter)->id << std::hex << "_" << _base << "_" <<  (*iter)->size << "." << ftype;

					 dump = NULL;
					 processBeforeDump((*iter)->data, (*iter)->size);
					 fopen_s(&dump, fpath.str().c_str(), "wb");
					 fwrite((*iter)->data, sizeof(char), (*iter)->size, dump);
					 fclose(dump);
			}
		}
	}

	Thread* MemoryArea::getThread(int id) const {
		if (id < THREAD_LIMIT) {
			std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();
			//LOG(string(__FUNCTION__) + ": get record for thread: "+ decstr(id) + " at ma " + decstr((*iter)->id) + "\n");
			return (*iter)->threads[id];
		}

		return 0;
	}

	void MemoryArea::addThread(Thread* thread) {
		if (thread && thread->ID() < THREAD_LIMIT) {
			std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();
			if ((*iter)->threads[thread->ID()] == 0) {
				(*iter)->threads[thread->ID()] = thread;
				// LOG(string(__FUNCTION__) + ": Adding record for thread: "+ decstr(thread->ID()) + " at ma " + decstr((*iter)->id) + "\n");
			}
		}
	}

	const char* MemoryArea::getLatestState(size_t& size) const {
		std::list<PLAYER>::const_reverse_iterator iter = ((std::list<PLAYER>*)(_states))->rbegin();

		size = (*iter)->size;
		return (*iter)->data;
	}

	bool MemoryArea::toJson( Json::Value& root ) const {
		std::list<PLAYER>::const_iterator iter;

		for (iter = ((std::list<PLAYER>*)(_states))->begin();
			 iter != ((std::list<PLAYER>*)(_states))->end(); iter++) {
				 Json::Value json_ma;
				 
				 json_ma["id"] = (*iter)->id;
				 json_ma["start"] = _base;
				 json_ma["end"] = (*iter)->size + _base;
				 json_ma["entry"] = (*iter)->entry;
				 json_ma["size"] = (*iter)->size;
				 json_ma["threads"] = Json::Value(Json::arrayValue);

				 for (int i = 0; i < THREAD_LIMIT; i++) {
				 	if ((*iter)->threads[i] != 0) {
				 		Json::Value thread;
				 		(*iter)->threads[i]->toJson(thread);
				 		if (!thread.empty())
				 			json_ma["threads"].append(thread);
				 	}
				 }

				 root.append(json_ma);
		}

		return true;
	}
}