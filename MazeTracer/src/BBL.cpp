#include "BBL.h"


namespace MazeWalker {
	int BasicBlock::_idGenerator = 0;

	BasicBlock::BasicBlock(int s, int e, int ins) {
		_start = s;
		_end = e;
		_ins_num = ins;
		_id = BasicBlock::_idGenerator++;
		_execs = 1;
	}

	bool BasicBlock::toJson( Json::Value& root ) const {
		root["id"] = _id;
		root["start"] = _start;
		root["end"] = _end;
		root["inst"] = _ins_num;
		root["reps"] = _execs;

		return true;
	}
}