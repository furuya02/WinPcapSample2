//***********************************************
//WinPcap.fs   wrote @furuya02  SIN/SAPPOROWORKS 
//***********************************************
module WinPcap

    #nowarn "9"
    open System
    open System.Text
    open System.Runtime.InteropServices

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type in_addr = 
        val b1 : char
        val b2 : char
        val b3 : char
        val b4 : char
        val w1 : UInt16
        val w2 : UInt16
        val addr : UInt64

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type sockaddr = 
        val family : Int16 //short
        val port : UInt16
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=4)>]
        val addr : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=8)>]
        val zero : System.Byte[]

    //*******************************************
    //pcap1.h
    //*******************************************
    // #define PCAP_IF_LOOPBACK	0x00000001	/* interface is loopback */
    let PCAP_IF_LOOPBACK = 0x00000001u

    //FILE *pcap_file(pcap_t *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_file(IntPtr p)


    //*******************************************
    //Win32-Extensions.h
    //*******************************************
    //HANDLE pcap_getevent(pcap_t *p);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_getevent(IntPtr p)

    //[Obsolete]int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_live_dump(IntPtr p, string filename, int maxsize, int maxpacks)

    //int pcap_live_dump_ended(pcap_t *p, int sync);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_live_dump_ended(IntPtr p, int sync)

    //pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_sendqueue_alloc(UInt32 memsize)
    
    //void pcap_sendqueue_destroy(pcap_send_queue* queue);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_sendqueue_destroy(IntPtr queue)

    //int pcap_sendqueue_queue(pcap_send_queue* queue, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_sendqueue_queue(IntPtr queue, IntPtr pkt_header, IntPtr pkt_data)

    //u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern UInt32 pcap_sendqueue_transmit(IntPtr p, IntPtr queue, int sync)




    //*******************************************
    //remote-ext.h
    //*******************************************
    //#define PCAP_BUF_SIZE 1024
    let PCAP_BUF_SIZE = 1024
    //#define PCAP_SRC_IF_STRING "rpcap://"
    let PCAP_SRC_IF_STRING = "rpcap://"
    //#define PCAP_SRC_FILE 2
    let PCAP_SRC_FILE = 2
    //#define PCAP_SRC_IFLOCAL 3
    let PCAP_SRC_IFLOCAL = 3
    //#define PCAP_SRC_IFREMOTE 4
    let PCAP_SRC_IFREMOTE = 4
    //#define PCAP_OPENFLAG_PROMISCUOUS		1
    let PCAP_OPENFLAG_PROMISCUOUS = 1

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type pcap_rmtauth = 
        val typ : int
        val username : string
        val password : string


    //int pcap_findalldevs_ex(char *source, struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf)
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_findalldevs_ex(string source, IntPtr auth,IntPtr *alldevs, StringBuilder errbuf)
    
    //pcap_t *pcap_open(const char *source, int snaplen, int flags, int read_timeout, struct pcap_rmtauth *auth, char *errbuf);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_open(string source, int snaplen, int flags, int read_timeout, IntPtr auth, StringBuilder errbuf)

    //SOCKET pcap_remoteact_accept(const char *address, const char *port, const char *hostlist, char *connectinghost, struct pcap_rmtauth *auth, char *errbuf);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern UIntPtr pcap_remoteact_accept(string address, string port, string hostlist, string connectinghost, IntPtr auth, StringBuilder errbuf)

    //void pcap_remoteact_cleanup();
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_remoteact_cleanup()

    //int pcap_remoteact_close(const char *host, char *errbuf);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_remoteact_close(string host, StringBuilder errbuf)

    //int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_remoteact_list(string address, string sep, int size, StringBuilder errbuf)


    //struct pcap_samp *pcap_setsampling(pcap_t *p);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_setsampling(IntPtr p)

    //*******************************************
    //bpf.h
    //*******************************************
    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type bpf_program = 
        val bf_len : UInt32
        val bf_insns :IntPtr



    //*******************************************
    //pcap.h
    //*******************************************
    let MODE_CAPT = 0
    let MODE_STAT = 1
    let MODE_MON = 2
    let PCAP_ERRBUF_SIZE = 256


    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type timeval = 
        val tv_sec : UInt32
        val tv_usec : UInt32

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type pcap_pkthdr =
        val ts : timeval
        val caplen : int
        val len : int

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type pcap_stat = 
        val ps_recv : UInt32
        val ps_drop : UInt32
        val ps_ifdrop : UInt32
        val bs_capt : UInt32

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type pcap_if = 
        val next : IntPtr
        val name : string
        val description : string
        val addresses : IntPtr
        val flags : UInt32

    [<Struct;StructLayout(LayoutKind.Sequential)>]
    type pcap_addr = 
        val next : IntPtr
        val addr : IntPtr
        val netmask : IntPtr
        val broadaddr : IntPtr
        val dstaddr : IntPtr

    //delegate void dispatcher_handler(IntPtr user, IntPtr header, IntPtr pkt_data)
    type dispatcher_handler = delegate of IntPtr * IntPtr * IntPtr -> unit

    //[Obsolete]char *pcap_lookupdev(char *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern string pcap_lookupdev(string errbuf)

    //[Obsolete]int pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_lookupnet(string device, UInt32 netp, UInt32 maskp, string errbuf)

    //pcap_t *pcap_create(const char *, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_createsrcstr(StringBuilder source, int typ, string host, string port, string name, StringBuilder errbuf)

    //pcap_t *pcap_open_live(const char *, int, int, int, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf)

    //pcap_t *pcap_open_dead(int, int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_open_dead(int linktype, int snaplen);


    //void	pcap_close(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_close(IntPtr p)

    //int pcap_loop(pcap_t *, int, pcap_handler, u_char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_loop(IntPtr p, int cnt, dispatcher_handler callback,IntPtr user)

    //int pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
    
    //const u_char* pcap_next(pcap_t *, struct pcap_pkthdr *);
    [<DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_next(IntPtr p, IntPtr h)

    //int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
    //[<DllImport("wpcap.dll", CharSet = CharSet.Ansi)>]
    [<DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl,CharSet = CharSet.Auto)>] 
    extern int pcap_next_ex(IntPtr p, IntPtr *pkt_header,IntPtr *pkt_data)


    //void pcap_breakloop(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_breakloop(IntPtr p)

    //int pcap_stats(pcap_t *, struct pcap_stat *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_stats(IntPtr p, IntPtr ps)

    //int pcap_setfilter(pcap_t *, struct bpf_program *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_setfilter(IntPtr p, IntPtr fp)

    //int pcap_setdirection(pcap_t *, pcap_direction_t);

    //int pcap_getnonblock(pcap_t *, char *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_getnonblock(IntPtr p, string errbuf)
    
    //int pcap_setnonblock(pcap_t *, int, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_setnonblock(IntPtr p, int nonblock, StringBuilder errbuf)
    
    //int pcap_sendpacket(pcap_t *, const u_char *, int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_sendpacket(IntPtr p, System.Byte[] buf, int size)

    //const char *pcap_strerror(int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern string pcap_strerror(int error)

    //char *pcap_geterr(pcap_t *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_geterr(IntPtr p)

    //int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_compile(IntPtr p, IntPtr fp, string str, int optimize, UInt32 netmask)

    //int pcap_compile_nopcap(int, int, struct bpf_program *,const char *, int, bpf_u_int32);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, IntPtr program, string buf, int optimize, UInt32 mask)
    
    //void pcap_freecode(struct bpf_program *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_freecode(IntPtr fp)


    //int pcap_datalink(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_datalink(IntPtr p)

    //int pcap_list_datalinks(pcap_t *, int **);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_list_datalinks(IntPtr p, IntPtr *dlt_buf)


    //int pcap_set_datalink(pcap_t *, int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_set_datalink(IntPtr p, int dlt)

    //int pcap_datalink_name_to_val(const char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_datalink_name_to_val(string name)

    //const char *pcap_datalink_val_to_name(int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_datalink_val_to_name(int dlt)

    //const char *pcap_datalink_val_to_description(int);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_datalink_val_to_description(int dlt)

    //int pcap_snapshot(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_snapshot(IntPtr p)

    //int pcap_is_swapped(pcap_t *);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_is_swapped(IntPtr p)

    //int pcap_major_version(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_major_version(IntPtr p);

    //int pcap_minor_version(pcap_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_minor_version(IntPtr p)

    //pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_dump_open(IntPtr p, string name)

    //pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp);

    //[Obsolete]FILE	*pcap_dump_file(pcap_dumper_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_dump_file(IntPtr p)

    //long	pcap_dump_ftell(pcap_dumper_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern Int64 pcap_dump_ftell(IntPtr p)

    //int pcap_dump_flush(pcap_dumper_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_dump_flush(IntPtr p)

    //void pcap_dump_close(pcap_dumper_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_dump_close(IntPtr p)
    
    //void pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_dump(IntPtr user, IntPtr h, IntPtr sp)
    
    //int pcap_findalldevs(pcap_if_t **, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Auto)>]
    extern int pcap_findalldevs(IntPtr * alldevsp, StringBuilder errbuf)
    
    //void pcap_freealldevs(pcap_if_t *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern void pcap_freealldevs(IntPtr alldevsp)

    //const char *pcap_lib_version(void);
    [<DllImport("packet.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern string pcap_lib_version()

    //pcap_t *pcap_open_offline(const char *, char *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_open_offline(string fname, StringBuilder errbuf)

    //int pcap_setbuff(pcap_t *p, int dim);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_setbuff(IntPtr p, int dim)

    //int pcap_setmode(pcap_t *p, int mode);    
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_setmode(IntPtr p, int mode)

    //int pcap_setmintocopy(pcap_t *p, int size);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern int pcap_setmintocopy(IntPtr p, int size)

    //int  pcap_stats_ex (pcap_t *, struct pcap_stat_ex *);
    [<DllImport("wpcap.dll",CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)>]
    extern IntPtr pcap_stats_ex(IntPtr p, IntPtr pcap_stat_size)
