#include "MemoryTracer.h"
#include "MemoryAreaMaker.h"
#include "WinAddress.h"
#include <list>
#include <map>
#include "PEImage.h"
#include "Blob.h"
#include "pin.H"


namespace MazeWalker {
    MemoryTracer::MemoryTracer() {
        _mas = new std::map<int, MemoryArea*>;
        _blob_reg = new std::list<IMemoryAreaMaker*>;
        _img_reg = new std::list<IImageMaker*>;

        // Register supported formats
        new ImageMaker<PEImage>;
        new MemoryAreaMaker<Blob>;
    }

    MemoryTracer& MemoryTracer::Instance() {
        static MemoryTracer tracer;
        return tracer;
    }

    void MemoryTracer::RegisterMemoryAreaType(IMemoryAreaMaker* maker) {
        ((std::list<IMemoryAreaMaker*>*)_blob_reg)->push_front(maker);
    }

    void MemoryTracer::RegisterImageType(IImageMaker* maker) {
        ((std::list<IImageMaker*>*)_img_reg)->push_front(maker);
    }

    MemoryArea* MemoryTracer::getMemoryArea(int address) {
        std::list<IMemoryAreaMaker*>::iterator blob_it;
        std::list<IImageMaker*>::iterator img_it;
        std::map<int, MemoryArea*>::iterator mas_it;
        std::list<IMemoryAreaMaker*>& blob_reg = *((std::list<IMemoryAreaMaker*>*)_blob_reg);
        std::list<IImageMaker*>& img_reg = *((std::list<IImageMaker*>*)_img_reg);
        std::map<int, MemoryArea*>& mas = *((std::map<int, MemoryArea*>*)_mas);
        MemoryArea *result = 0;
        IAddress& addr = WinAddress(address);


        mas_it = mas.find(addr.Base());
        if (mas_it == mas.end()) {
            for (img_it = img_reg.begin(); img_it != img_reg.end(); img_it++) {
                result = (*img_it)->Create(address, addr.Base(), addr.Size(), NULL);
                if (result) {
                    mas[addr.Base()] = result;
                    return result;
                }
            }

            for (blob_it = blob_reg.begin(); blob_it != blob_reg.end(); blob_it++) {
                result = (*blob_it)->Create(address, addr.Base(), addr.Size());
                if ( result ) {
                    mas[addr.Base()] = result;
                    break;
                }
            }
        }

        return mas[addr.Base()];
    }

    Image* MemoryTracer::CreateImage(void* imgObj) {
        int base, size, entry;
        const char* path;
        std::list<IImageMaker*>::iterator it;
        std::map<int, MemoryArea*>::iterator mas_it;
        std::list<IImageMaker*>& reg = *((std::list<IImageMaker*>*)_img_reg);
        std::map<int, MemoryArea*>& mas = *((std::map<int, MemoryArea*>*)_mas);

        if (IMG_Valid(*((IMG*)imgObj))) {
            base = IMG_StartAddress(*((IMG*)imgObj));
            size = IMG_HighAddress(*((IMG*)imgObj)) - IMG_LowAddress(*((IMG*)imgObj));
            entry = IMG_Entry(*((IMG*)imgObj));
            path = IMG_Name(*((IMG*)imgObj)).c_str();

            mas_it = mas.find(base);
            if (mas_it == mas.end()) {
                for (it = reg.begin(); it != reg.end(); it++) {
                    if (mas[base] = (*it)->Create(entry, base, size, path))
                        break;
                }
            }

            return (Image*)(mas[base]);
        }

        return NULL;
    }
}