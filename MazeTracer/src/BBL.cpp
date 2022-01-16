#include "BBL.h"
#include "cJSON.h"


namespace MazeWalker {
    int BasicBlock::_idGenerator = 0;

    BasicBlock::BasicBlock(int s, int e, int ins) {
        _start = s;
        _end = e;
        _ins_num = ins;
        _id = BasicBlock::_idGenerator++;
        _execs = 1;
    }

    bool BasicBlock::toJson(void* root ) const {
        if (root == NULL) return false;

        cJSON_AddNumberToObject((cJSON*)root, "id", _id);
        cJSON_AddNumberToObject((cJSON*)root, "start", _start);
        cJSON_AddNumberToObject((cJSON*)root, "end", _end);
        cJSON_AddNumberToObject((cJSON*)root, "inst", _ins_num);
        cJSON_AddNumberToObject((cJSON*)root, "reps", _execs);

        return true;
    }
}