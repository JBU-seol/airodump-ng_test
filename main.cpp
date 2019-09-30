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
static map<int,struct data> m_data;
static map<int,struct data>::iterator iter;
static int count=1;//key
static int data_count=1;


void saveInfo(char* device,std::mutex& mutex){
    struct pcap_pkthdr* header;
    const u_char* packet;
    char *dev = device;
    struct data info;
    info.beacons=1;
    info.frame=1;
    uint8_t over=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
    if(handle == nullptr){
        printf("Can't open device %s %s \n",dev,errbuf);

    }


    while(1){
        //printf("saveInfo\n");

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
                    count ++;
                    mutex.unlock();
                }
            }

        }
        else if( beacon_p->type_subtype == PROBE_REQUEST_TYPE){
            info.pwr = alfa_p->af_sig1;
            memcpy(info.s_add,beacon_p->s_addr,6);
            if(*wire_p == 0x00){
                wire_p ++;
                info.essid_len=*wire_p;
                memcpy(info.essid,(wire_p+1),info.essid_len);
            }
            if(m_data.empty()){
                mutex.lock();
                m_data[data_count] = info;
                data_count++;
                mutex.unlock();
            }
            else{
                for( iter = m_data.begin(); iter != m_data.end(); iter++){
                    if( (*iter).second.s_add[0]== info.s_add[0] && (*iter).second.s_add[1]== info.s_add[1]
                            && (*iter).second.s_add[2]== info.s_add[2] && (*iter).second.s_add[3]== info.s_add[3]
                            && (*iter).second.s_add[4]== info.s_add[4] && (*iter).second.s_add[5]== info.s_add[5]){
                        mutex.lock();
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.frame ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m_data[data_count] = info;
                    data_count ++;
                    mutex.unlock();
                }
            }

        }
        /*
        else if( beacon_p->type_subtype == PROBE_RESPONSE_TYPE){
            info.pwr = alfa_p->af_sig1;
            memcpy(info.s_add,beacon_p->d_addr,6);
            memcpy(info.bssid,beacon_p->bssid,6);
            if(*wire_p == 0x00){
                wire_p ++;
                info.essid_len=*wire_p;
                memcpy(info.essid,(wire_p+1),info.essid_len);
            }
            if(m_data.empty()){
                mutex.lock();
                m_data[data_count] = info;
                data_count++;
                mutex.unlock();
            }
            else{
                for( iter = m_data.begin(); iter != m_data.end(); iter++){
                    if( (*iter).second.bssid[0]== info.bssid[0] && (*iter).second.bssid[1]== info.bssid[1]
                            && (*iter).second.bssid[2]== info.bssid[2] && (*iter).second.bssid[3]== info.bssid[3]
                            && (*iter).second.bssid[4]== info.bssid[4] && (*iter).second.bssid[5]== info.bssid[5]
                            && (*iter).second.s_add[0]== info.s_add[0] && (*iter).second.s_add[1]== info.s_add[1]
                            && (*iter).second.s_add[2]== info.s_add[2] && (*iter).second.s_add[3]== info.s_add[3]
                            && (*iter).second.s_add[4]== info.s_add[4] && (*iter).second.s_add[5]== info.s_add[5]){
                        mutex.lock();
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.frame ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m_data[data_count] = info;
                    data_count ++;
                    mutex.unlock();
                }
            }
        }
        */
        else if( beacon_p->type_subtype == QOS_TYPE  ){
            info.pwr = alfa_p->af_sig1;
            info.essid_len=0;
            memcpy(info.bssid,beacon_p->s_addr,6);
            memcpy(info.s_add,beacon_p->d_addr,6);
            if(m_data.empty()){
                mutex.lock();
                m_data[data_count] = info;
                data_count++;
                mutex.unlock();
            }
            else{
                for( iter = m_data.begin(); iter != m_data.end(); iter++){
                    if( (*iter).second.bssid[0]== info.bssid[0] && (*iter).second.bssid[1]== info.bssid[1]
                            && (*iter).second.bssid[2]== info.bssid[2] && (*iter).second.bssid[3]== info.bssid[3]
                            && (*iter).second.bssid[4]== info.bssid[4] && (*iter).second.bssid[5]== info.bssid[5]
                            && (*iter).second.s_add[0]== info.s_add[0] && (*iter).second.s_add[1]== info.s_add[1]
                            && (*iter).second.s_add[2]== info.s_add[2] && (*iter).second.s_add[3]== info.s_add[3]
                            && (*iter).second.s_add[4]== info.s_add[4] && (*iter).second.s_add[5]== info.s_add[5]){
                        mutex.lock();
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.frame ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m_data[data_count] = info;
                    data_count ++;
                    mutex.unlock();
                }
            }
        }
        else if(beacon_p->type_subtype == QOS_NULL_TYPE){
            info.pwr = alfa_p->af_sig1;
            info.essid_len=0;
            memcpy(info.bssid,beacon_p->bssid,6);
            memcpy(info.s_add,beacon_p->s_addr,6);
            if(m_data.empty()){
                mutex.lock();
                m_data[data_count] = info;
                data_count++;
                mutex.unlock();
            }
            else{
                for( iter = m_data.begin(); iter != m_data.end(); iter++){
                    if( (*iter).second.bssid[0]== info.bssid[0] && (*iter).second.bssid[1]== info.bssid[1]
                            && (*iter).second.bssid[2]== info.bssid[2] && (*iter).second.bssid[3]== info.bssid[3]
                            && (*iter).second.bssid[4]== info.bssid[4] && (*iter).second.bssid[5]== info.bssid[5]
                            && (*iter).second.s_add[0]== info.s_add[0] && (*iter).second.s_add[1]== info.s_add[1]
                            && (*iter).second.s_add[2]== info.s_add[2] && (*iter).second.s_add[3]== info.s_add[3]
                            && (*iter).second.s_add[4]== info.s_add[4] && (*iter).second.s_add[5]== info.s_add[5]){
                        mutex.lock();
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.frame ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m_data[data_count] = info;
                    data_count ++;
                    mutex.unlock();
                }
            }
        }
        else if( beacon_p->type_subtype == NULL_TYPE1 || beacon_p->type_subtype == NULL_TYPE2 ){
            info.pwr = alfa_p->af_sig1;
            info.essid_len=0;
            memcpy(info.bssid,beacon_p->bssid,6);
            memcpy(info.s_add,beacon_p->s_addr,6);
            if(m_data.empty()){
                mutex.lock();
                m_data[data_count] = info;
                data_count++;
                mutex.unlock();
            }
            else{
                for( iter = m_data.begin(); iter != m_data.end(); iter++){
                    if( (*iter).second.bssid[0]== info.bssid[0] && (*iter).second.bssid[1]== info.bssid[1]
                            && (*iter).second.bssid[2]== info.bssid[2] && (*iter).second.bssid[3]== info.bssid[3]
                            && (*iter).second.bssid[4]== info.bssid[4] && (*iter).second.bssid[5]== info.bssid[5]
                            && (*iter).second.s_add[0]== info.s_add[0] && (*iter).second.s_add[1]== info.s_add[1]
                            && (*iter).second.s_add[2]== info.s_add[2] && (*iter).second.s_add[3]== info.s_add[3]
                            && (*iter).second.s_add[4]== info.s_add[4] && (*iter).second.s_add[5]== info.s_add[5]){
                        mutex.lock();
                        (*iter).second.pwr = info.pwr;
                        (*iter).second.frame ++;
                        over = 1;
                        mutex.unlock();
                        break;
                    }
                    else
                        over = 0;
                }
                if( over == 0 ){
                    mutex.lock();
                    m_data[data_count] = info;
                    data_count ++;
                    mutex.unlock();
                }
            }
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
        printf("\nBSSID                        STATION         PWR            fames         Probe\n");
        //data print
        for( iter= m_data.begin(); iter != m_data.end(); iter++){
            for(int i=0;i<6;i++){
                printf("%02X",(*iter).second.bssid[i]);
                if(i != 5)
                    printf(":");
                else
                    printf("\t");
            }
            for(int i=0;i<6;i++){
                printf("%02X",(*iter).second.s_add[i]);
                if(i != 5)
                    printf(":");
                else
                    printf("\t");
            }
            printf("%d\t\t%d\t",(*iter).second.pwr,(*iter).second.frame);
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
    system("ifconfig wlan1 down");
    system("iwconfig wlan1 mode monitor");
    system("ifconfig wlan1 up");


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
