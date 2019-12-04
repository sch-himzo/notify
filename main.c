#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>
#include <pcap.h>
#include <string.h>

#define MAX_PRINT 80
#define MAX_LINE 16
#define DATASHIFT 54
#define PCAP_SRC_IF_STRING "rpcap://"

void usage();
int pushToSlack(int msgCode);

void main(int argc, char **argv)
{
	int embMachineState = 0;
	int embMachinePrevState = 0;
	int stitchCount = 0;
	int counter = 0;
	int x,y = 0;
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *source = NULL;
	char *ofilename = NULL;
	char *filterarg = NULL;
	char filter[50];
	int i;
	pcap_dumper_t *dumpfile;
	struct bpf_program fcode;
	bpf_u_int32 NetMask;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char *url = NULL;

	if (argc != 7)
	{
		if (argc == 2 && argv[1][1] == 'l')
		{
			if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
			{
				fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
				return -1;
			}

			/* Print adapter list */
			for (d = alldevs; d; d = d->next)
			{
				printf("%d. %s\n    ", ++y, d->name);

				if (d->description)
					printf(" (%s)\n", d->description);
				else
					printf(" (No description available)\n");
			}

			if (y == 0)
			{
				fprintf(stderr, "No interfaces found! Exiting.\n");
				return -1;
			}
			return 0;
		}
		usage();
		return;
	}

	for (i = 1; i < argc; i += 2)
	{

		switch (argv[i][1])
		{
		case 's':
		{
			source = argv[i + 1];
		};
		break;
		case 'u':
		{
			url = argv[i + 1];
		};
		break;

		case 'm':
		{
			filter[0] = "\0";
			filterarg = argv[i + 1];
			strcpy(filter, "src ");
			strcat(filter, filterarg);
			strcat(filter, " and tcp");
		};
		break;
		}
	}

	// open a capture from the network
	if (source != NULL)
	{
		if ((fp = pcap_open(source,
			1514 /*snaplen*/,
			1 /*flags*/,
			20 /*read timeout*/,
			NULL /* remote authentication */,
			errbuf)
			) == NULL)
		{
			printf("\nUnable to open the adapter.\n");
			return;
		}
	}

	else usage();

	if (filter != NULL)
	{
		// We should loop through the adapters returned by the pcap_findalldevs_ex()
		// in order to locate the correct one.
		//
		// Let's do things simpler: we suppose to be in a C class network ;-)
		NetMask = 0xffffff;

		//compile the filter
		if (pcap_compile(fp, &fcode, filter, 1, NetMask) < 0)
		{
			printf("\nError compiling filter: wrong syntax.\n");
			return;
		}

		//set the filter
		if (pcap_setfilter(fp, &fcode) < 0)
		{
			printf("\nError setting the filter\n");
			return;
		}

	}

	//start the capture
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
        counter++;
		if (res == 0)
			/* Timeout elapsed */
			continue;

		
		//Print out hex and decimal data for debug purposes
		/*printf("%d\n", pkt_data[17]);
		for (x = DATASHIFT; x < pkt_data[17] + 14; x++)
		{
			printf("%03x ", pkt_data[x]);
		}
		printf("\n");
		for (x = DATASHIFT; x < pkt_data[17] + 14; x++)
		{
			printf("%03d ", pkt_data[x]);
		}
		printf("\n\n");*/

		//Check condition if machine is running
		if (pkt_data[DATASHIFT + 3] == 73 && pkt_data[DATASHIFT + 7] == 71)
		{
			//Calculate actual stitch number
			int num2 = ((int)pkt_data[DATASHIFT + 15] | (int)pkt_data[DATASHIFT + 16] << 8 | (int)pkt_data[DATASHIFT + 17] << 16 | (int)pkt_data[DATASHIFT + 18] << 24) - 1024;
			//printf("\nStitch: %d\n", num2);
		}else{
		    int num2 = 0;
		}
		else {
			//If machine is not running, find out the reason
			switch (pkt_data[DATASHIFT + 7])
			{
			case 68:
				if (pkt_data[DATASHIFT + 8] == 68)
				{
					embMachineState = 68;
					//printf("\nRUNNUNG\n");
					break;
				}
				if (pkt_data[DATASHIFT + 8] == 70)
				{
					embMachineState = 4;
						//printf("\nEND\n");
						break;
				}
				break;
			case 83:
				switch (pkt_data[DATASHIFT + 8])
				{
				case 69:
					embMachineState = 3;
					//printf("\nMACHINE ERROR\n");
					break;
				case 77:
					embMachineState = 4;
					//printf("\nEND\n");
					break;
				case 78:
					embMachineState = 0;
					//printf("\nSTOP SWITCH\n");
					break;
				case 83:
					embMachineState = 1;
					//printf("\nNEEDLE STOP\n");
					break;
				case 84:
					embMachineState = 2;
					//printf("\nTHREAD BREAK\n");
					break;
				}
			}

			//check if machine state has changed
			if (embMachineState != embMachinePrevState)
			{
				//post slack message
				pushToSlack(embMachineState, url);
				embMachinePrevState = embMachineState;
			}


			if(counter%100){
			    pushToWebsite(embMachineState,num2);
			}
		}
		

	}
}


void usage()
{

	printf("\nHimzoNoti - HappyLAN Machine State extractor with Slack integration\n");
	printf("\nUsage:  himzonoti -s source -u slack_url  -m machine_ip\n");
	printf("\nIf not sure what the source adapter is, use -l switch to list available network adapters.\n\n");
	
	exit(0);
}

int pushToWebsite(int code, int stitch)
{
    CURL *curl;
    CURLcode resCurl;
    curl_global_init(CURL_GLOBAL_ALL);
    struct curl_slist *headers = NULL;
    char url[1024] = "http://himzo.sch.bme.hu/api/machine/state/";
    char* machine_key = "asd123";
    char str_code[2];
    char str_stitch[10];

    sprintf(str_code,"%d",code);
    if(stitch!=0){
        sprintf(str_stitch,"%d",stitch);
    }else{
        str_code[0] = '\0';
    }

    strcpy(url,machine_key);
    strcpy(url,"/");
    strcpy(url,str_code);
    strcpy(url,"/");
    if(str_code!=""){
        strcpy(url,str_stitch);
    }

    curl = curl_easy_init();
    if(curl){
        curl_easy_setopt(curl, CURLOPT_URL, url);
        headers = curl_slist_append(headers, "Expect:");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        resCurl = curl_easy_perform(curl);
        /* Check for errors */
        if (resCurl != CURLE_OK)
        {
            printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(resCurl));
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        }
    }else{
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;

}

int pushToSlack(int msgcode, char* url)
{

	//curl for post request
	CURL *curl;
	CURLcode resCurl;
	curl_global_init(CURL_GLOBAL_ALL);
	struct curl_slist *headers = NULL;

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		headers = curl_slist_append(headers, "Expect:");
		headers = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		switch (msgcode)
		{
		case 3:
			printf("\nMACHINE ERROR\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Gephiba (???)\"}");
			break;
		case 4:
			printf("\nEND\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Kesz a himzes\"}");
			break;
		case 0:
			printf("\nSTOP SWITCH\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Megallitva\"}");
			break;
		case 1:
			printf("\nNEEDLE STOP\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Elore beallitott STOP\"}");
			break;
		case 2:
			printf("\nTHREAD BREAK\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Szalszakadas!\"}");
			break;
		case 68:
			printf("\nRUNNING\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"Elinditva\"}");
			break;

		default:
			printf("\nApplication Error No.420 - Angus nem tud programozni\n");
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "{\"text\":\"\nApplication Error No.420 - Angus nem tud programozni\n\"}");
			break;

		}

		resCurl = curl_easy_perform(curl);

		/* Check for errors */
		if (resCurl != CURLE_OK)
		{
			printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(resCurl));
			curl_easy_cleanup(curl);
			curl_global_cleanup();
			return 1;
		}
	}
	else {
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return 1;
	}

		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return 0;
	}
	