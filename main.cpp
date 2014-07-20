#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <sstream>
#include <sg_lib.h>
#include <sg_pt.h>

#include <boost/program_options.hpp>
#define LOBYTE(v) *((unsigned char*)&v)

#pragma pack(push, 1)
typedef struct {
    unsigned char unk[0x2];
	unsigned char vendorStrLen2;
	unsigned char productStrLen2;
	unsigned char unk2[8];
    unsigned short idVendor;
    unsigned short idProduct;
    unsigned short bcdDevice;
    unsigned char iManufacter;
    unsigned char iProduct;
    unsigned char unk3[2];
    unsigned char vendorStrLength; // This includes the field itself too till the end of the string
    unsigned char vendorStrDescType; // 0x03
} AlcorSCSIRebuildPart1;
//Next is vendor string , each character followed by 0x00


typedef struct {
    unsigned char productStrLength;// This includes the field itself too till the end of the string
    unsigned char productStrDescType; //0x03
    
} AlcorSCSIRebuildPart2;

//Next is product string

//Followed by SCSI String terminated by 0xF0
std::string parseUsbDescStr(unsigned char * start,int len)
{
    std::stringstream ss;
    for ( int i = 0; i < len; i+= 2 )
        ss << start[i];
    return ss.str();
}


typedef struct {
  char headerMagic[16];
  int unk1;
  int unk2;
  int unk3;
  int unk4;
  int unk5; // 1
  int version; //Confirmed?
  int entry_size; // Confirmed?
  int entry_count;
    
} AlcorFlashListHeader;
typedef struct {
  unsigned char vendor[16];
  unsigned char partno[32];
  unsigned char id[6];
  unsigned char unk1[0xb];
  unsigned char CE;
  /*unsigned char unk2[14];
  unsigned char cache_enabled;*/
  unsigned char unk[0x260-(1+0xb)];
} AlcorFlashListEntry;
#pragma pack(pop)
// It seems to be some kind of block cipher using 0x100 ( 256 bytes) blocks
unsigned char * init_Vector(const unsigned char * enc_key , int keylen, unsigned char * out)
{
    int v4;
    unsigned int v3;
    unsigned int v5;
    unsigned int v6;
    unsigned int v7;

    unsigned char * res = NULL;
    if ( enc_key && out )
    {
        v4 = 0;
        v3 = 0;
        do {
            out[v3] = v3;
            ++v3;

        } while ( v3 < 0x100 );
        v5 = 0;
        do
        {
            v6 = v5 / keylen;
            v7 = v5 % keylen;
            LOBYTE(v6) = enc_key[v5 % keylen];
            LOBYTE(v7) = out[v5];
            v4 = (v7 + v4 + v6) & 0xFF;
            LOBYTE(v7) = out[v4] ^ v7;
            out[v5] = v7;
            LOBYTE(v7) = v7 ^ out[v4];
            out[v4] = v7;
            out[v5++] ^= v7;


        } while ( v5 < 0x100 );
        res = out;
    } else {
        res = 0;
    }
    return res;
}
void * decryptBlock(unsigned char * buffer, int bufferlen, const unsigned char * enc_key, int keylen, unsigned char * output)
{
    unsigned char * v5; // edi@3
    int v6; // eax@4
    int v7; // edx@4
    int v8; // ecx@4
    unsigned char *v9; // esi@4
    int v10; // ebp@5
    unsigned char v11; // bl@6
    unsigned char v12; // bl@6
    unsigned char v13; // bl@6
    unsigned char* result; // eax@8
    int v16; // [sp+10h] [bp+4h]@5

    if ( buffer && enc_key && ( v5 = output, output ))
    {
        v9 = new unsigned char[0x100];
        init_Vector(enc_key, keylen, v9);
        v7 = bufferlen;
        v6 = 0;
        v8 = 0;
        if ( bufferlen )
        {
            v10 = buffer - output;
            v16 = bufferlen;
            do
            {
                v6 = (v6 + 1) & 0xFF;
                LOBYTE(v7) = v9[v6];
                v8 = (v8 + v7) & 0xFF;
                v11 = v9[v8] ^ v9[v6];
                v9[v6] = v11;
                v12 = v11 ^ v9[v8];
                v9[v8] = v12;
                v13 = v12 ^ v9[v6];
                v9[v6] = v13;
                *v5 = v5[v10] ^ v9[(v9[v8] + v13) % 256];
                ++v5;
                v7 = v16 - 1;
            }
            while ( v16-- != 1 );
            v5 = output;
        }
        delete[] v9;
        result = v5;

    }
}
int main(int argc, char **argv) {
    
    
    boost::program_options::options_description desc("Options:");
    desc.add_options()
        ("help","Show usage")
        ("flashlist",boost::program_options::value<std::string>(),"flashlist.afl path")
        ("detectflash","Try to detect device's flash chip")
        ("fetchinfo","Print drive's information")
        ("setconfig",boost::program_options::value<std::string>(),"Set config raw data")
        ("getconfig",boost::program_options::value<std::string>(),"Save config raw data to file")
        ("setvendorstr",boost::program_options::value<std::string>(),"Set vendor string descriptor ( DANGEROUS )")
        ("device",boost::program_options::value<std::string>(),"SCSI device ( /dev/sdX )");
     
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc,argv,desc),vm);
    boost::program_options::notify(vm);
    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }
    if ( vm.count("detectflash") && vm.count("flashlist") && vm.count("device") )
    {
        FILE * f = fopen(vm["flashlist"].as<std::string>().c_str(),"rb");
        unsigned char buffer[512];
        fread(buffer,512,1,f);
        unsigned char out1[256];
        decryptBlock(buffer,256,(const unsigned char*)"ALCORFLASHCFG_SZ",16,out1);
        unsigned char out2[512];
        decryptBlock(&buffer[256],256,out1,256,out2);
        
    // fwrite(out2,256,1,stdout);
        AlcorFlashListHeader hdr;
        memcpy(&hdr,out2,sizeof(hdr));
        printf("File version: %d\n",hdr.version);
        printf("Entry size: %d\n",hdr.entry_size);
        printf("Entry count: %d\n",hdr.entry_count);
        
        unsigned char * completebuffer = new unsigned char[std::min(1024*1024*128, hdr.entry_size*hdr.entry_count)];
        unsigned char * completebuffer_enc = new unsigned char[std::min(1024*1024*128, hdr.entry_size*hdr.entry_count)];
        memset(completebuffer,0,hdr.entry_size*hdr.entry_count);
        
        int nb = fread(completebuffer_enc,1,hdr.entry_count*hdr.entry_size,f);
        if ( nb != hdr.entry_count*hdr.entry_size )
            abort();
        for ( int i = 0; i < hdr.entry_count; i++ )
        {
            out1[0] = i;
            out1[255] = ~(i + (unsigned char)0 /*a4*/);
            decryptBlock(&completebuffer_enc[hdr.entry_size*i],hdr.entry_size,out1,256,&completebuffer[hdr.entry_size*i]);
        }
        //fwrite(completebuffer,1,hdr.entry_size*hdr.entry_count,stdout);
        std::map<std::string,AlcorFlashListEntry*> flashlist;
        AlcorFlashListEntry * entries = (AlcorFlashListEntry*)completebuffer;
        FILE * outDebug = fopen("decrypted.bin","wb");
        fwrite(completebuffer,1,std::min(1024*1024*128, hdr.entry_size*hdr.entry_count),outDebug);
        fclose(outDebug);
        for ( int i = 0; i < hdr.entry_count; i++ )
        {
        // printf("%s - %s , ID: %02x%02x%02x%02x%02x%02x ",entries[i].vendor,entries[i].partno,entries[i].id[0],entries[i].id[1],entries[i].id[2],entries[i].id[3],entries[i].id[4],entries[i].id[5]);
            char piece[64];
            sprintf(piece,"%02x%02x%02x%02x%02x%02x",entries[i].id[0],entries[i].id[1],entries[i].id[2],entries[i].id[3],entries[i].id[4],entries[i].id[5]);
            if ( flashlist.find(std::string(piece)) != flashlist.end() )
            {
                printf("Duplicate flash %s , CE: %d, unk[5] = %d\n",piece,(int)entries[i].CE,(int)entries[i].unk1[5]);
            }
            flashlist[piece] = &entries[i];
            /*   if ( !entries[i].cache_enabled )
            {
                printf("-No cache enabled-");
            }*/
            
        // printf(" CE = %d, ADD Data:",entries[i].CE);
        /*  for ( int k = 0; k < 32; k++ )
            {
                
                printf("%02x",entries[i].unk1[k]);
                
            }
            printf("\n");*/
        }
        int scsi_fd;
        struct sg_pt_base *ptvp = NULL;
        scsi_fd = scsi_pt_open_device(vm["device"].as<std::string>().c_str(),0,0);
        ptvp = construct_scsi_pt_obj();
        unsigned char cdb[] = { 0xfa , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00, 0x00 };
        set_scsi_pt_cdb(ptvp,cdb,8);
        unsigned char result[10];
        set_scsi_pt_data_in(ptvp,result,10);
        do_scsi_pt(ptvp,scsi_fd,10,0);
        int data_len = 10 - get_scsi_pt_resid(ptvp);
        
        std::stringstream ss;
        for ( int k = 0; k < 6; k++ )
        {
            char piece[10];
            sprintf(piece,"%02x",result[k]);
            ss << piece;
            printf("%02x",result[k]);
            
        }
        printf("\n");
        if ( flashlist.find(ss.str()) != flashlist.end() )
        {
            printf("%s %s\n",flashlist[ss.str()]->vendor, flashlist[ss.str()]->partno );
            
        }
        
        return 0;
        
    }
    if ( vm.count("fetchinfo") && vm.count("device") )
    {
        int scsi_fd;
        struct sg_pt_base *ptvp = NULL;
        
        scsi_fd = scsi_pt_open_device(vm["device"].as<std::string>().c_str(),0,0);
        ptvp = construct_scsi_pt_obj();
        set_scsi_pt_flags(ptvp,0x0);
        unsigned char cdb[] = { 0x82 , 0x51 , 0x01 , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00 };
        set_scsi_pt_cdb(ptvp,cdb,10);
        unsigned char result[512];
        set_scsi_pt_data_in(ptvp,result,512);
        do_scsi_pt(ptvp,scsi_fd,512,0);
        
        int data_len = 512 - get_scsi_pt_resid(ptvp);
        
        AlcorSCSIRebuildPart1 * p1 = (AlcorSCSIRebuildPart1*)result;
        printf("Vendor ID: %04x , Product ID: %04x\n",p1->idVendor,p1->idProduct);
        unsigned char * strpointer1 = result;
        strpointer1 += sizeof(AlcorSCSIRebuildPart1);
        printf("Vendor String: %s",parseUsbDescStr(strpointer1,p1->vendorStrLength-2).c_str());
        strpointer1 += p1->vendorStrLength-2;
        AlcorSCSIRebuildPart2 * p2 = (AlcorSCSIRebuildPart2*)strpointer1;
        strpointer1 += sizeof(AlcorSCSIRebuildPart2);
        printf(", Product String: %s\n",parseUsbDescStr(strpointer1,p2->productStrLength-2).c_str());
        scsi_pt_close_device(scsi_fd);
        return 0;
    }
    if ( vm.count("getconfig") && vm.count("device") )
    {
        int scsi_fd;
        struct sg_pt_base *ptvp = NULL;
        scsi_fd = scsi_pt_open_device(vm["device"].as<std::string>().c_str(),0,0);
        ptvp = construct_scsi_pt_obj();
        unsigned char cdb[] = { 0x82 , 0x51 , 0x01 , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00 };
        set_scsi_pt_cdb(ptvp,cdb,10);
        unsigned char result[512];
        set_scsi_pt_data_in(ptvp,result,512);
        do_scsi_pt(ptvp,scsi_fd,512,0);
        int data_len = 512 - get_scsi_pt_resid(ptvp);
        
        FILE * out = fopen(vm["getconfig"].as<std::string>().c_str(),"wb");
        fwrite(result,1,512,out);
        fclose(out);
        std::cout << "Config downloaded." << std::endl;
		scsi_pt_close_device(scsi_fd);
        return 0;
    }
    if ( vm.count("setconfig") && vm.count("device") )
    {
        int scsi_fd;
        struct sg_pt_base *ptvp = NULL;
        scsi_fd = scsi_pt_open_device(vm["device"].as<std::string>().c_str(),0,0);
        ptvp = construct_scsi_pt_obj();
        unsigned char cdb2[] = { 0x81 , 0x00  , 0xff , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
        unsigned char newconfig[512];
        FILE * f = fopen(vm["setconfig"].as<std::string>().c_str(),"rb");
        fread(newconfig,1,512,f);
        fclose(f);
        set_scsi_pt_cdb(ptvp,cdb2,16);
        set_scsi_pt_data_out(ptvp,newconfig,512);
        do_scsi_pt(ptvp,scsi_fd,512,0);
        destruct_scsi_pt_obj(ptvp);
        std::cout << "Config uploaded." << std::endl;
		scsi_pt_close_device(scsi_fd);
		return 0;
    }
    if ( vm.count("setvendorstr") && vm.count("device") )
    {
        std::string newvendor = vm["setvendorstr"].as<std::string>();
        std::cout << newvendor << std::endl;
        int scsi_fd;
        struct sg_pt_base *ptvp = NULL;
        scsi_fd = scsi_pt_open_device(vm["device"].as<std::string>().c_str(),0,0);
        ptvp = construct_scsi_pt_obj();
        unsigned char cdb[] = { 0x82 , 0x51 , 0x01 , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00 };
        set_scsi_pt_cdb(ptvp,cdb,10);
        unsigned char result[512];
        set_scsi_pt_data_in(ptvp,result,512);
        do_scsi_pt(ptvp,scsi_fd,512,0);
        
        
        int data_len = 512 - get_scsi_pt_resid(ptvp);
        destruct_scsi_pt_obj(ptvp);
        ptvp = construct_scsi_pt_obj();
        if ( data_len != 0 )
        {
            std::cerr << "Unexpected error while retrieving current configuration, " << data_len << std::endl;
            return 1;
        }
        if ( result[0] != 0x99 || result[1] != 0x07 )
        {
            std::cerr << "Invalid data , aborting..." << std::endl;
            return 1;
        }
        cdb[0] = 0x81; // SCSI Rebuild
        cdb[1] = 0x00;
        cdb[2] = 0xff;
        unsigned char cdb2[] = { 0x81 , 0x00  , 0xff , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
        unsigned char newconfig[512];
        memset(newconfig,0,512);
        memcpy(newconfig,result,sizeof(AlcorSCSIRebuildPart1));
        AlcorSCSIRebuildPart1 * p1 = (AlcorSCSIRebuildPart1*)newconfig;
        AlcorSCSIRebuildPart1 * p1_old = (AlcorSCSIRebuildPart1*)result;
        p1->vendorStrLength = newvendor.length()*2+2;
        p1->vendorStrLen2 = newvendor.length()*2+2;
        unsigned char* strpointer1 = &newconfig[sizeof(AlcorSCSIRebuildPart1)];
        for ( int i = 0; i < newvendor.length(); i++ )
        {
            *(strpointer1++) = newvendor.c_str()[i];
            *(strpointer1++) = 0x00;
        }
        memcpy(strpointer1,&result[sizeof(AlcorSCSIRebuildPart1)+p1_old->vendorStrLength-2],0x46);
        strpointer1 += strpointer1[0]+0x1c; // 0x1c should be SCSI length
        
        
        //The byte we are on now , is special , it seems to be the sum of all preceding bytes with bitwise and on 0xff
        unsigned int sum1 = 0;
        for ( unsigned char * ptr = newconfig; ptr < strpointer1; ptr++ )
           sum1 += *ptr; 
        *strpointer1 = sum1 & 0xff;
      // memset(strpointer1,0,0x52);
        
        
        newconfig[0x7e] = 0x3C; newconfig[0x7f] = 0xC3;
        
        memcpy(&newconfig[0x80],&result[0x80],0x2c);
        newconfig[0xc3] = 0x02; newconfig[0xc7] = 0x02;
        
        newconfig[0xd4] = 0x88; newconfig[0xd5] = 0x50; newconfig[0xd6] = 0x51; newconfig[0xd7] = 0x49; // 0x88,PQI
        set_scsi_pt_cdb(ptvp,cdb2,16);
        set_scsi_pt_data_out(ptvp,newconfig,512);
        FILE * ff = fopen("outconfig.bin","wb");
        fwrite(newconfig,1,512,ff);
        fclose(ff);
        do_scsi_pt(ptvp,scsi_fd,512,0);
        destruct_scsi_pt_obj(ptvp);
      /*  ptvp = construct_scsi_pt_obj();
       unsigned char cdb3[] = { 0x82 , 0x51 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00, 0x00,0x00,0x00 }; //Regenerate
        set_scsi_pt_cdb(ptvp,cdb3,10);
        set_scsi_pt_data_in(ptvp,result,512);
        set_scsi_pt_data_out(ptvp,NULL,0);
        do_scsi_pt(ptvp,scsi_fd,512,0);*/
        
	  
	   scsi_pt_close_device(scsi_fd);
        
    }
    
    return 1;
}
//sub_10004680
