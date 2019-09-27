#include <iostream>
#include <pcap/pcap.h>
#include <map>
#include <thread>
#include <array>
#include <mutex>
#include <cstring>
#include <unistd.h>
#include "header.h"

using namespace std;

static map<int,struct data> m;
static map<int,struct data>::iterator iter;
static int count=1;//key


void saveInfo(char* device,std::mutex& mutex){
    struct pcap_pkthdr* header;
    const u_char* packet;
    char *dev = device;
    struct data info;
    info.beacons=0;
    uint8_t over=0;


    while(1){
        //printf("saveInfo\n");
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
        if(handle == nullptr){
            printf("Can't open device %s %s \n",dev,errbuf);
        }
        int red1=pcap_next_ex(handle, &header, &packet);
        if(red1 == 0){
            printf("packet reading error !\n");
        }
        int check=0;
        radiotap *radio_p = (radiotap *)packet;
        alfa *alfa_p = (alfa *)(packet+sizeof(radiotap));
        beacons *beacon_p = (beacons *)(packet + (radio_p->it_len) );
        uint8_t *wire_p = (uint8_t *)(packet + sizeof(radiotap) + sizeof(alfa) + sizeof(beacons)+sizeof(fixed_header));

        if( beacon_p->type_subtype == BEACONS_TYPE){
            //printf("%04X",beacon_p->type_subtype);
            for(int i=0;i<6;i++) info.bssid[i]=beacon_p->bssid[i];
            //for(int i=0;i<6;i++) printf("aaaa%02X:",info.bssid[i]);
            info.pwr = alfa_p->af_sig1;
            info.channel = (uint8_t)(alfa_p->af_fre - CHANNEL_STANDARD) /5 +1;

            while(1){
                switch(*wire_p){
                case 0x00:{
                    wire_p ++;
                    info.essid_len=*wire_p;
                    memcpy(info.essid,(wire_p+1),info.essid_len);
                    wire_p += *(wire_p);
                    wire_p ++;
                    check++;//find 1;
                    break;
                }
                case 0x2a :{
                    wire_p++;
                    wire_p += *(wire_p);
                    wire_p++;
                    if(*(wire_p)==0x32){// Tag RSN
                        info.encrypt=1;//OPN
                        //printf("OPN\n");
                        check++;//find 2
                    }
                    break;
                }
                case 0x30 :{
                    wire_p++;
                    wire_p += *(wire_p);
                    wire_p++;
                    info.encrypt=2;//WPA2
                    //printf("WPA2\n");
                    check++;//find 2
                    break;
                }
                default:{
                    wire_p++;
                    wire_p += *(wire_p);
                    wire_p++;
                    break;

                }
                }
                if(check == 2)
                    break;
            }

            if(m.empty())
            {
                mutex.lock();
                m[count]=info;
                count ++ ;
                mutex.unlock();
            }
            else
            {
                for( iter = m.begin(); iter != m.end(); iter++){
                    if( (*iter).second.bssid[0]== info.bssid[0] && (*iter).second.bssid[1]== info.bssid[1]
                            && (*iter).second.bssid[2]== info.bssid[2] && (*iter).second.bssid[3]== info.bssid[3]
                            && (*iter).second.bssid[4]== info.bssid[4] && (*iter).second.bssid[5]== info.bssid[5]){
                        mutex.lock();
                        //for(int i=0;i<6;i++) printf("bbbb%02X:",(*iter).second.bssid[i]);
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.beacons ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m[count] = info;
                    //for(int i=0;i<6;i++) printf("cccc%02X:",m[count].bssid[i]);
                    printf("\n");
                    count ++;
                    mutex.unlock();
                }
            }

        }
        else if( beacon_p->type_subtype == DATA_TYPE ){
            printf("Not Yet ...\n");
        }

    }

}


void printInfo(std::mutex& mutex){

    while(1){
        //printf("printInfo\n");
        mutex.lock();

        printf("BSSID                    PWR       Beacons       CH     ENC     ESSID\n\n");
        for( iter= m.begin(); iter != m.end(); iter++){
            for(int i=0;i<6;i++){
                printf("%02X",(*iter).second.bssid[i]);
                if(i != 5)
                    printf(":");
                else
                    printf("\t");
            }
            printf("%d\t\t%d\t%d\t",(*iter).second.pwr,(*iter).second.beacons,(*iter).second.channel);
            if((*iter).second.encrypt == 1)
                printf("OPN");
            else if((*iter).second.encrypt == 2)
                printf("WPA2");
            printf("\t");
            for(int i=0;i< (*iter).second.essid_len; i++){
                printf("%c",(*iter).second.essid[i]);
            }
            printf("\n");
        }
        mutex.unlock();
        sleep(1);
        system("clear");
    }
}

/*
void pp(std::mutex& m){
    m.lock();
    int i=0;
    while(1){
        printf("%d\n",i);
        i++;
        if(i==100)
            break;
    }
    m.unlock();
}

void ppp(std::mutex& m){
    m.lock();
    for(int i=0;i<100;i++){
        printf("%d\n",i*1000);
    }
    m.unlock();
}*/

int main(int argc, char* argv[])
{
    if(argc < 2){
        printf("Check your parameters. ex)airodump_test wlan0 \n");
        return -1;
    }
    std::mutex mutex;//ref(mutex)   mutex.lock   unlock
    std::thread fun1(saveInfo,argv[1],ref(mutex));
    std::thread fun2(printInfo,ref(mutex));
    fun1.join();
    fun2.join();
    /*std::thread fun1(pp,std::ref(mutex));
    std::thread fun2(ppp,std::ref(mutex));
    fun1.join();
    fun2.join();*/
    //--------Channel = (rad->af_fre-CHANNEL_STANDARD) /5 +1 -----------

    return 0;

}
