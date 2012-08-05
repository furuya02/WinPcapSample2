//******************************************************
//Program.fs  wrote @furuya02  SIN/SAPPOROWORKS 
//******************************************************
#nowarn "9"
#nowarn "51"

open System
open System.Runtime.InteropServices
open System.Text
open System.Threading
open System.Net
open System.Collections.Specialized

//******************************************************
//htons htonl
//******************************************************
let htons(n:Int16) =
    IPAddress.HostToNetworkOrder(n)
let htonl(n:Int32) =
    IPAddress.HostToNetworkOrder(n)

//******************************************************
//文字列への変換
//******************************************************
let macStr(buf:byte[]) = 
    sprintf "%02x:%02x:%02x:%02x:%02x:%02x" (buf.[0]) (buf.[1]) (buf.[2]) (buf.[3]) (buf.[4]) (buf.[5])
let ipStr(buf:byte[])=
    (new IPAddress(buf)).ToString()

//******************************************************
//ヘッダ表示
//******************************************************
let dispHeda(hdr:WinPcap.pcap_pkthdr)=
    printf "size=%dbyte " hdr.len 

//***********************************e*******************
//Ether表示
//******************************************************
let dispEther(buf:byte[])=
    printfn "%s => %s protocol=0x%02x%02x" (macStr(buf.[6..11])) (macStr(buf.[0..5])) buf.[12] buf.[13]
    match (buf.[12],buf.[13]) with
    | 0x08uy,0x00uy -> "IPv4"
    | 0x08uy,0x06uy -> "ARP"
    | 0x86uy,0xdduy -> "IPv6"
    |_ -> sprintf "%02x%02x" buf.[12] buf.[13]
    
//******************************************************
//ダンプ表示
//******************************************************
let dispDump(buf:byte[],offset:int) = 
    let max = if buf.Length > 30 then 30 else buf.Length-1
    [offset..max]
    |>Seq.iter(fun i -> printf "%02x" buf.[i])
    printfn ""

//******************************************************
//ARP表示
//******************************************************
[<Struct;StructLayout(LayoutKind.Sequential)>]
    type ArpHeader = 
        val hardwareType : UInt16
        val protocolType : UInt16
        val hardwareSize : byte
        val protocolSize : byte
        val opcode : Int16
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=6)>]
        val srcMac : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=4)>]
        val srcIp : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=6)>]
        val dstMac : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=4)>]
        val dstIp : System.Byte[]
let dispArp(buf:byte[],offset:int) = 
    //構造体へのコピー
    let s = Marshal.SizeOf(typeof<ArpHeader>)//構造体のサイズ
    let p = Marshal.AllocHGlobal(s)//メモリ確保
    Marshal.Copy(buf, offset,p,s)
    let h = Marshal.PtrToStructure(p, typeof<ArpHeader>):?>ArpHeader //ヘッダ構造体への変換
    //変換
    let opcode = htons(h.opcode) //制御コード
    let srcIp = ipStr(h.srcIp) //送り元IP
    let dstIp = ipStr(h.dstIp) //送り元MAC
    let srcMac = macStr(h.srcMac) //宛て先IP
    let dstMac = macStr(h.dstMac) //宛て先MAC
    //表示
    match opcode with
    |0x0001s -> printfn " ARP Who has %s? Tell %s" dstIp srcIp //ARO要求
    |0x0002s -> printfn " ARP %s is at %s" srcIp srcMac //ARP応答
    |_ -> printfn " ARP opcode=%d src=%s(%s) dst=%s(%s)" opcode srcIp srcMac dstIp dstMac
    Marshal.FreeHGlobal(p)//メモリ解放

//******************************************************
//IPv6表示
//******************************************************
[<Struct;StructLayout(LayoutKind.Sequential)>]
    type IPv6Header = 
        val Ver_TrafficClass_FlowLabel : BitVector32
        val PayloadLength : Int16
        val NextHeader : byte
        val HopLimit : byte
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=16)>]
        val srcIp : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=16)>]
        val dstIp : System.Byte[]
let dispIPv6(buf:byte[],offset:int) = 
    //構造体へのコピー
    let s = Marshal.SizeOf(typeof<IPv6Header>)//構造体のサイズ
    let p = Marshal.AllocHGlobal(s)//メモリ確保
    Marshal.Copy(buf, offset,p,s)
    let h = Marshal.PtrToStructure(p, typeof<IPv6Header>):?>IPv6Header //ヘッダ構造体への変換
    //変換
    let srcIp = ipStr(h.srcIp)
    let dstIp = ipStr(h.dstIp)
    let payloadLength = htons(h.PayloadLength)
    let NextHeader = 
        match h.NextHeader with
        | 0x00uy -> "ICMP Option(hop by hop)"
        | 0x01uy -> "ICMP"
        | 0x02uy -> "IGMP"
        | 0x03uy -> "IP"
        | 0x06uy -> "TCP"
        | 0x11uy -> "UDP"
        | 0x29uy -> "IPv6"
        | 0x3auy -> "ICMPv6"
        | 0x3buy -> "No Next Header"
        |_ -> sprintf "0x%02x" h.NextHeader
    //表示
    printfn " IPv6 src=%s dst=%s payloadLength=%d hopLimit=%d nextHeader=%s" srcIp dstIp payloadLength h.HopLimit NextHeader
    Marshal.FreeHGlobal(p)//メモリ解放

//******************************************************
//IPv4表示
//******************************************************
[<Struct;StructLayout(LayoutKind.Sequential)>]
    type IPv4Header = 
        val VerLen : byte
        val TOS : byte
        val TotalLength : UInt16
        val Id : UInt16
        val OffSet: UInt16
        val TTL : byte
        val Protocol : byte
        val Checksum : UInt16
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=4)>]
        val srcIp : System.Byte[]
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst=4)>]
        val dstIp : System.Byte[]

let dispIPv4(buf:byte[],offset:int) = 
    //構造体へのコピー
    let s = Marshal.SizeOf(typeof<IPv4Header>)//構造体のサイズ
    let p = Marshal.AllocHGlobal(s)//メモリ確保
    Marshal.Copy(buf, offset,p,s)
    let h = Marshal.PtrToStructure(p, typeof<IPv4Header>):?>IPv4Header //ヘッダ構造体への変換
    //変換
    let srcIp = ipStr(h.srcIp) //送り元IPアドレス
    let dstIp = ipStr(h.dstIp) //宛先IPアドレス
    let protocol = match h.Protocol with
                   | 1uy -> "ICMP"
                   | 2uy -> "IGMP"
                   | 6uy -> "TCP"
                   | 8uy -> "EGP"
                   | 9uy -> "IGP"
                   | 17uy -> "UDP"
                   | 41uy -> "IPv6"
                   | 43uy -> "IPv6-Route"
                   | 44uy -> "IPv6-Frag"
                   | 58uy -> "IPv6-ICMP"
                   | 59uy -> "IPv6-NoNext"
                   | 60uy -> "IPv6-Opts"
                   | 68uy -> "IPv6-ICMP"
                   | 88uy -> "EIGRP"
                   | 89uy -> "OSPF"
                   | 115uy -> "L2TP"
                   |_ -> sprintf "0x%02x" h.Protocol
    //表示
    printfn " IPv4 proto=%s src=%s dst=%s ttl=%d check=0x%04x" protocol srcIp dstIp h.TTL h.Checksum
    Marshal.FreeHGlobal(p)//メモリ解放

//******************************************************
//１パケットの表示
//******************************************************
let disp(pkt_data:IntPtr,pkt_hdr:IntPtr) = 
    //ヘッダ取得
    let hdr = Marshal.PtrToStructure(pkt_hdr,typeof<WinPcap.pcap_pkthdr>):?>WinPcap.pcap_pkthdr
    //データ取得
    let data:byte[] = Array.zeroCreate hdr.caplen
    Marshal.Copy(pkt_data,data,0,(int)(hdr.caplen))
    
    dispHeda(hdr)//ヘッダ表示
    let offset = ref(14)//オフセット移動
    match dispEther(data) with //Ether表示
    | "ARP" -> dispArp(data,!offset)//ARP表示
    | "IPv4" -> dispIPv4(data,!offset)//IPv4表示
    | "IPv6" -> dispIPv6(data,!offset)//IPv6表示
    |_ -> dispDump(data,!offset)//ダンプ表示

//******************************************************
//キャプチャ開始(ループ)
//******************************************************
let capture devName =
    printfn "%s" devName  //デバイス名表示
    let MAX_RECV_SIZE = 1600 //受信バッファサイズ
    let timeout = 20 //タイムアウト
    let Promiscast = 1 //プロミスキャスモード
    let ebuf = new StringBuilder(WinPcap.PCAP_ERRBUF_SIZE) //エラーメッセージ取得バッファ
    let handle = WinPcap.pcap_open(devName,MAX_RECV_SIZE,Promiscast,timeout,IntPtr.Zero,ebuf)
    
    let mutable pkt_data = new IntPtr();
    let mutable pkt_hdr = new IntPtr();
    while true do //受信ループ
        match WinPcap.pcap_next_ex(handle, &&pkt_hdr,&&pkt_data) with //データ取得
        | -1 -> printfn "ERROR" //エラー
        | 0 -> Thread.Sleep(1)//タイムアウト(データ受信なし)
        | _ -> disp(pkt_data,pkt_hdr)|>ignore//１パケットの表示
   
   
//******************************************************
//main
//******************************************************
//デバイス一覧取得
let devs =
    [
    let mutable alldevs = IntPtr()//情報取得用のバッファ
    let ebuf = new StringBuilder(WinPcap.PCAP_ERRBUF_SIZE) //エラーメッセージ取得バッファ
    if WinPcap.pcap_findalldevs_ex("rpcap://",IntPtr.Zero,&&alldevs,ebuf) <> -1 then
        let p = ref(alldevs)
        while (!p <> IntPtr.Zero) do
            let pcap_if = Marshal.PtrToStructure(!p,typeof<WinPcap.pcap_if>) :?> WinPcap.pcap_if
            yield pcap_if
            p := pcap_if.next 
    ]

//デバイス一覧の表示
[0..devs.Length-1]|>List.iter(fun i -> printfn "%d %s" (i+1) devs.[i].description)

//デバイス選択
printf "\nモニタするデバイスを選択してください\n[1-%d] >" devs.Length
let key = Console.ReadKey()
let index = int(key.KeyChar)-49 //'1'->0 , '2'->1 , '3'->2 変換

//選択が有効かどうかの判定
if 0<= index && index<devs.Length then
    capture devs.[index].name //キャプチャ開始(ループ)
else 
    printfn "無効なデバイスを選択しました"|>ignore
         
