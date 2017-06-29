#ifndef _MAZEWALKER_TYPES_H
#define _MAZEWALKER_TYPES_H

#if defined(_MSC_VER)
typedef unsigned __int8 MAZE_UINT8 ;
typedef unsigned __int16 MAZE_UINT16;
typedef unsigned __int32 MAZE_UINT32;
typedef unsigned __int64 MAZE_UINT64;
typedef __int8 MAZE_INT8;
typedef __int16 MAZE_INT16;
typedef __int32 MAZE_INT32;
typedef __int64 MAZE_INT64;
#else
typedef uint8_t  MAZE_UINT8;
typedef uint16_t MAZE_UINT16;
typedef uint32_t MAZE_UINT32;
typedef uint64_t MAZE_UINT64;
typedef int8_t  MAZE_INT8;
typedef int16_t MAZE_INT16;
typedef int32_t MAZE_INT32;
typedef int64_t MAZE_INT64;
# endif

#ifdef OS64
#define U_INT MAZE_UINT64
#else
#define U_INT MAZE_UINT32
#endif

#endif