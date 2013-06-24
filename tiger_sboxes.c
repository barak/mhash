
#include "libdefs.h"

#ifdef TIGER_64BIT

/*
   sboxes.c: Tiger S boxes 
 */
word64 table[4 * 256] =
{
	0x02AAB17CF7E90C5ELL		/*
								   0 
								 */ , 0xAC424B03E243A8ECLL
								/*
								   1 
								 */ ,
	0x72CD5BE30DD5FCD3LL		/*
								   2 
								 */ , 0x6D019B93F6F97F3ALL
								/*
								   3 
								 */ ,
	0xCD9978FFD21F9193LL		/*
								   4 
								 */ , 0x7573A1C9708029E2LL
								/*
								   5 
								 */ ,
	0xB164326B922A83C3LL		/*
								   6 
								 */ , 0x46883EEE04915870LL
								/*
								   7 
								 */ ,
	0xEAACE3057103ECE6LL		/*
								   8 
								 */ , 0xC54169B808A3535CLL
								/*
								   9 
								 */ ,
	0x4CE754918DDEC47CLL		/*
								   10 
								 */ , 0x0AA2F4DFDC0DF40CLL
								/*
								   11 
								 */ ,
	0x10B76F18A74DBEFALL		/*
								   12 
								 */ , 0xC6CCB6235AD1AB6ALL
								/*
								   13 
								 */ ,
	0x13726121572FE2FFLL		/*
								   14 
								 */ , 0x1A488C6F199D921ELL
								/*
								   15 
								 */ ,
	0x4BC9F9F4DA0007CALL		/*
								   16 
								 */ , 0x26F5E6F6E85241C7LL
								/*
								   17 
								 */ ,
	0x859079DBEA5947B6LL		/*
								   18 
								 */ , 0x4F1885C5C99E8C92LL
								/*
								   19 
								 */ ,
	0xD78E761EA96F864BLL		/*
								   20 
								 */ , 0x8E36428C52B5C17DLL
								/*
								   21 
								 */ ,
	0x69CF6827373063C1LL		/*
								   22 
								 */ , 0xB607C93D9BB4C56ELL
								/*
								   23 
								 */ ,
	0x7D820E760E76B5EALL		/*
								   24 
								 */ , 0x645C9CC6F07FDC42LL
								/*
								   25 
								 */ ,
	0xBF38A078243342E0LL		/*
								   26 
								 */ , 0x5F6B343C9D2E7D04LL
								/*
								   27 
								 */ ,
	0xF2C28AEB600B0EC6LL		/*
								   28 
								 */ , 0x6C0ED85F7254BCACLL
								/*
								   29 
								 */ ,
	0x71592281A4DB4FE5LL		/*
								   30 
								 */ , 0x1967FA69CE0FED9FLL
								/*
								   31 
								 */ ,
	0xFD5293F8B96545DBLL		/*
								   32 
								 */ , 0xC879E9D7F2A7600BLL
								/*
								   33 
								 */ ,
	0x860248920193194ELL		/*
								   34 
								 */ , 0xA4F9533B2D9CC0B3LL
								/*
								   35 
								 */ ,
	0x9053836C15957613LL		/*
								   36 
								 */ , 0xDB6DCF8AFC357BF1LL
								/*
								   37 
								 */ ,
	0x18BEEA7A7A370F57LL		/*
								   38 
								 */ , 0x037117CA50B99066LL
								/*
								   39 
								 */ ,
	0x6AB30A9774424A35LL		/*
								   40 
								 */ , 0xF4E92F02E325249BLL
								/*
								   41 
								 */ ,
	0x7739DB07061CCAE1LL		/*
								   42 
								 */ , 0xD8F3B49CECA42A05LL
								/*
								   43 
								 */ ,
	0xBD56BE3F51382F73LL		/*
								   44 
								 */ , 0x45FAED5843B0BB28LL
								/*
								   45 
								 */ ,
	0x1C813D5C11BF1F83LL		/*
								   46 
								 */ , 0x8AF0E4B6D75FA169LL
								/*
								   47 
								 */ ,
	0x33EE18A487AD9999LL		/*
								   48 
								 */ , 0x3C26E8EAB1C94410LL
								/*
								   49 
								 */ ,
	0xB510102BC0A822F9LL		/*
								   50 
								 */ , 0x141EEF310CE6123BLL
								/*
								   51 
								 */ ,
	0xFC65B90059DDB154LL		/*
								   52 
								 */ , 0xE0158640C5E0E607LL
								/*
								   53 
								 */ ,
	0x884E079826C3A3CFLL		/*
								   54 
								 */ , 0x930D0D9523C535FDLL
								/*
								   55 
								 */ ,
	0x35638D754E9A2B00LL		/*
								   56 
								 */ , 0x4085FCCF40469DD5LL
								/*
								   57 
								 */ ,
	0xC4B17AD28BE23A4CLL		/*
								   58 
								 */ , 0xCAB2F0FC6A3E6A2ELL
								/*
								   59 
								 */ ,
	0x2860971A6B943FCDLL		/*
								   60 
								 */ , 0x3DDE6EE212E30446LL
								/*
								   61 
								 */ ,
	0x6222F32AE01765AELL		/*
								   62 
								 */ , 0x5D550BB5478308FELL
								/*
								   63 
								 */ ,
	0xA9EFA98DA0EDA22ALL		/*
								   64 
								 */ , 0xC351A71686C40DA7LL
								/*
								   65 
								 */ ,
	0x1105586D9C867C84LL		/*
								   66 
								 */ , 0xDCFFEE85FDA22853LL
								/*
								   67 
								 */ ,
	0xCCFBD0262C5EEF76LL		/*
								   68 
								 */ , 0xBAF294CB8990D201LL
								/*
								   69 
								 */ ,
	0xE69464F52AFAD975LL		/*
								   70 
								 */ , 0x94B013AFDF133E14LL
								/*
								   71 
								 */ ,
	0x06A7D1A32823C958LL		/*
								   72 
								 */ , 0x6F95FE5130F61119LL
								/*
								   73 
								 */ ,
	0xD92AB34E462C06C0LL		/*
								   74 
								 */ , 0xED7BDE33887C71D2LL
								/*
								   75 
								 */ ,
	0x79746D6E6518393ELL		/*
								   76 
								 */ , 0x5BA419385D713329LL
								/*
								   77 
								 */ ,
	0x7C1BA6B948A97564LL		/*
								   78 
								 */ , 0x31987C197BFDAC67LL
								/*
								   79 
								 */ ,
	0xDE6C23C44B053D02LL		/*
								   80 
								 */ , 0x581C49FED002D64DLL
								/*
								   81 
								 */ ,
	0xDD474D6338261571LL		/*
								   82 
								 */ , 0xAA4546C3E473D062LL
								/*
								   83 
								 */ ,
	0x928FCE349455F860LL		/*
								   84 
								 */ , 0x48161BBACAAB94D9LL
								/*
								   85 
								 */ ,
	0x63912430770E6F68LL		/*
								   86 
								 */ , 0x6EC8A5E602C6641CLL
								/*
								   87 
								 */ ,
	0x87282515337DDD2BLL		/*
								   88 
								 */ , 0x2CDA6B42034B701BLL
								/*
								   89 
								 */ ,
	0xB03D37C181CB096DLL		/*
								   90 
								 */ , 0xE108438266C71C6FLL
								/*
								   91 
								 */ ,
	0x2B3180C7EB51B255LL		/*
								   92 
								 */ , 0xDF92B82F96C08BBCLL
								/*
								   93 
								 */ ,
	0x5C68C8C0A632F3BALL		/*
								   94 
								 */ , 0x5504CC861C3D0556LL
								/*
								   95 
								 */ ,
	0xABBFA4E55FB26B8FLL		/*
								   96 
								 */ , 0x41848B0AB3BACEB4LL
								/*
								   97 
								 */ ,
	0xB334A273AA445D32LL		/*
								   98 
								 */ , 0xBCA696F0A85AD881LL
								/*
								   99 
								 */ ,
	0x24F6EC65B528D56CLL		/*
								   100 
								 */ , 0x0CE1512E90F4524ALL
								/*
								   101 
								 */ ,
	0x4E9DD79D5506D35ALL		/*
								   102 
								 */ , 0x258905FAC6CE9779LL
								/*
								   103 
								 */ ,
	0x2019295B3E109B33LL		/*
								   104 
								 */ , 0xF8A9478B73A054CCLL
								/*
								   105 
								 */ ,
	0x2924F2F934417EB0LL		/*
								   106 
								 */ , 0x3993357D536D1BC4LL
								/*
								   107 
								 */ ,
	0x38A81AC21DB6FF8BLL		/*
								   108 
								 */ , 0x47C4FBF17D6016BFLL
								/*
								   109 
								 */ ,
	0x1E0FAADD7667E3F5LL		/*
								   110 
								 */ , 0x7ABCFF62938BEB96LL
								/*
								   111 
								 */ ,
	0xA78DAD948FC179C9LL		/*
								   112 
								 */ , 0x8F1F98B72911E50DLL
								/*
								   113 
								 */ ,
	0x61E48EAE27121A91LL		/*
								   114 
								 */ , 0x4D62F7AD31859808LL
								/*
								   115 
								 */ ,
	0xECEBA345EF5CEAEBLL		/*
								   116 
								 */ , 0xF5CEB25EBC9684CELL
								/*
								   117 
								 */ ,
	0xF633E20CB7F76221LL		/*
								   118 
								 */ , 0xA32CDF06AB8293E4LL
								/*
								   119 
								 */ ,
	0x985A202CA5EE2CA4LL		/*
								   120 
								 */ , 0xCF0B8447CC8A8FB1LL
								/*
								   121 
								 */ ,
	0x9F765244979859A3LL		/*
								   122 
								 */ , 0xA8D516B1A1240017LL
								/*
								   123 
								 */ ,
	0x0BD7BA3EBB5DC726LL		/*
								   124 
								 */ , 0xE54BCA55B86ADB39LL
								/*
								   125 
								 */ ,
	0x1D7A3AFD6C478063LL		/*
								   126 
								 */ , 0x519EC608E7669EDDLL
								/*
								   127 
								 */ ,
	0x0E5715A2D149AA23LL		/*
								   128 
								 */ , 0x177D4571848FF194LL
								/*
								   129 
								 */ ,
	0xEEB55F3241014C22LL		/*
								   130 
								 */ , 0x0F5E5CA13A6E2EC2LL
								/*
								   131 
								 */ ,
	0x8029927B75F5C361LL		/*
								   132 
								 */ , 0xAD139FABC3D6E436LL
								/*
								   133 
								 */ ,
	0x0D5DF1A94CCF402FLL		/*
								   134 
								 */ , 0x3E8BD948BEA5DFC8LL
								/*
								   135 
								 */ ,
	0xA5A0D357BD3FF77ELL		/*
								   136 
								 */ , 0xA2D12E251F74F645LL
								/*
								   137 
								 */ ,
	0x66FD9E525E81A082LL		/*
								   138 
								 */ , 0x2E0C90CE7F687A49LL
								/*
								   139 
								 */ ,
	0xC2E8BCBEBA973BC5LL		/*
								   140 
								 */ , 0x000001BCE509745FLL
								/*
								   141 
								 */ ,
	0x423777BBE6DAB3D6LL		/*
								   142 
								 */ , 0xD1661C7EAEF06EB5LL
								/*
								   143 
								 */ ,
	0xA1781F354DAACFD8LL		/*
								   144 
								 */ , 0x2D11284A2B16AFFCLL
								/*
								   145 
								 */ ,
	0xF1FC4F67FA891D1FLL		/*
								   146 
								 */ , 0x73ECC25DCB920ADALL
								/*
								   147 
								 */ ,
	0xAE610C22C2A12651LL		/*
								   148 
								 */ , 0x96E0A810D356B78ALL
								/*
								   149 
								 */ ,
	0x5A9A381F2FE7870FLL		/*
								   150 
								 */ , 0xD5AD62EDE94E5530LL
								/*
								   151 
								 */ ,
	0xD225E5E8368D1427LL		/*
								   152 
								 */ , 0x65977B70C7AF4631LL
								/*
								   153 
								 */ ,
	0x99F889B2DE39D74FLL		/*
								   154 
								 */ , 0x233F30BF54E1D143LL
								/*
								   155 
								 */ ,
	0x9A9675D3D9A63C97LL		/*
								   156 
								 */ , 0x5470554FF334F9A8LL
								/*
								   157 
								 */ ,
	0x166ACB744A4F5688LL		/*
								   158 
								 */ , 0x70C74CAAB2E4AEADLL
								/*
								   159 
								 */ ,
	0xF0D091646F294D12LL		/*
								   160 
								 */ , 0x57B82A89684031D1LL
								/*
								   161 
								 */ ,
	0xEFD95A5A61BE0B6BLL		/*
								   162 
								 */ , 0x2FBD12E969F2F29ALL
								/*
								   163 
								 */ ,
	0x9BD37013FEFF9FE8LL		/*
								   164 
								 */ , 0x3F9B0404D6085A06LL
								/*
								   165 
								 */ ,
	0x4940C1F3166CFE15LL		/*
								   166 
								 */ , 0x09542C4DCDF3DEFBLL
								/*
								   167 
								 */ ,
	0xB4C5218385CD5CE3LL		/*
								   168 
								 */ , 0xC935B7DC4462A641LL
								/*
								   169 
								 */ ,
	0x3417F8A68ED3B63FLL		/*
								   170 
								 */ , 0xB80959295B215B40LL
								/*
								   171 
								 */ ,
	0xF99CDAEF3B8C8572LL		/*
								   172 
								 */ , 0x018C0614F8FCB95DLL
								/*
								   173 
								 */ ,
	0x1B14ACCD1A3ACDF3LL		/*
								   174 
								 */ , 0x84D471F200BB732DLL
								/*
								   175 
								 */ ,
	0xC1A3110E95E8DA16LL		/*
								   176 
								 */ , 0x430A7220BF1A82B8LL
								/*
								   177 
								 */ ,
	0xB77E090D39DF210ELL		/*
								   178 
								 */ , 0x5EF4BD9F3CD05E9DLL
								/*
								   179 
								 */ ,
	0x9D4FF6DA7E57A444LL		/*
								   180 
								 */ , 0xDA1D60E183D4A5F8LL
								/*
								   181 
								 */ ,
	0xB287C38417998E47LL		/*
								   182 
								 */ , 0xFE3EDC121BB31886LL
								/*
								   183 
								 */ ,
	0xC7FE3CCC980CCBEFLL		/*
								   184 
								 */ , 0xE46FB590189BFD03LL
								/*
								   185 
								 */ ,
	0x3732FD469A4C57DCLL		/*
								   186 
								 */ , 0x7EF700A07CF1AD65LL
								/*
								   187 
								 */ ,
	0x59C64468A31D8859LL		/*
								   188 
								 */ , 0x762FB0B4D45B61F6LL
								/*
								   189 
								 */ ,
	0x155BAED099047718LL		/*
								   190 
								 */ , 0x68755E4C3D50BAA6LL
								/*
								   191 
								 */ ,
	0xE9214E7F22D8B4DFLL		/*
								   192 
								 */ , 0x2ADDBF532EAC95F4LL
								/*
								   193 
								 */ ,
	0x32AE3909B4BD0109LL		/*
								   194 
								 */ , 0x834DF537B08E3450LL
								/*
								   195 
								 */ ,
	0xFA209DA84220728DLL		/*
								   196 
								 */ , 0x9E691D9B9EFE23F7LL
								/*
								   197 
								 */ ,
	0x0446D288C4AE8D7FLL		/*
								   198 
								 */ , 0x7B4CC524E169785BLL
								/*
								   199 
								 */ ,
	0x21D87F0135CA1385LL		/*
								   200 
								 */ , 0xCEBB400F137B8AA5LL
								/*
								   201 
								 */ ,
	0x272E2B66580796BELL		/*
								   202 
								 */ , 0x3612264125C2B0DELL
								/*
								   203 
								 */ ,
	0x057702BDAD1EFBB2LL		/*
								   204 
								 */ , 0xD4BABB8EACF84BE9LL
								/*
								   205 
								 */ ,
	0x91583139641BC67BLL		/*
								   206 
								 */ , 0x8BDC2DE08036E024LL
								/*
								   207 
								 */ ,
	0x603C8156F49F68EDLL		/*
								   208 
								 */ , 0xF7D236F7DBEF5111LL
								/*
								   209 
								 */ ,
	0x9727C4598AD21E80LL		/*
								   210 
								 */ , 0xA08A0896670A5FD7LL
								/*
								   211 
								 */ ,
	0xCB4A8F4309EBA9CBLL		/*
								   212 
								 */ , 0x81AF564B0F7036A1LL
								/*
								   213 
								 */ ,
	0xC0B99AA778199ABDLL		/*
								   214 
								 */ , 0x959F1EC83FC8E952LL
								/*
								   215 
								 */ ,
	0x8C505077794A81B9LL		/*
								   216 
								 */ , 0x3ACAAF8F056338F0LL
								/*
								   217 
								 */ ,
	0x07B43F50627A6778LL		/*
								   218 
								 */ , 0x4A44AB49F5ECCC77LL
								/*
								   219 
								 */ ,
	0x3BC3D6E4B679EE98LL		/*
								   220 
								 */ , 0x9CC0D4D1CF14108CLL
								/*
								   221 
								 */ ,
	0x4406C00B206BC8A0LL		/*
								   222 
								 */ , 0x82A18854C8D72D89LL
								/*
								   223 
								 */ ,
	0x67E366B35C3C432CLL		/*
								   224 
								 */ , 0xB923DD61102B37F2LL
								/*
								   225 
								 */ ,
	0x56AB2779D884271DLL		/*
								   226 
								 */ , 0xBE83E1B0FF1525AFLL
								/*
								   227 
								 */ ,
	0xFB7C65D4217E49A9LL		/*
								   228 
								 */ , 0x6BDBE0E76D48E7D4LL
								/*
								   229 
								 */ ,
	0x08DF828745D9179ELL		/*
								   230 
								 */ , 0x22EA6A9ADD53BD34LL
								/*
								   231 
								 */ ,
	0xE36E141C5622200ALL		/*
								   232 
								 */ , 0x7F805D1B8CB750EELL
								/*
								   233 
								 */ ,
	0xAFE5C7A59F58E837LL		/*
								   234 
								 */ , 0xE27F996A4FB1C23CLL
								/*
								   235 
								 */ ,
	0xD3867DFB0775F0D0LL		/*
								   236 
								 */ , 0xD0E673DE6E88891ALL
								/*
								   237 
								 */ ,
	0x123AEB9EAFB86C25LL		/*
								   238 
								 */ , 0x30F1D5D5C145B895LL
								/*
								   239 
								 */ ,
	0xBB434A2DEE7269E7LL		/*
								   240 
								 */ , 0x78CB67ECF931FA38LL
								/*
								   241 
								 */ ,
	0xF33B0372323BBF9CLL		/*
								   242 
								 */ , 0x52D66336FB279C74LL
								/*
								   243 
								 */ ,
	0x505F33AC0AFB4EAALL		/*
								   244 
								 */ , 0xE8A5CD99A2CCE187LL
								/*
								   245 
								 */ ,
	0x534974801E2D30BBLL		/*
								   246 
								 */ , 0x8D2D5711D5876D90LL
								/*
								   247 
								 */ ,
	0x1F1A412891BC038ELL		/*
								   248 
								 */ , 0xD6E2E71D82E56648LL
								/*
								   249 
								 */ ,
	0x74036C3A497732B7LL		/*
								   250 
								 */ , 0x89B67ED96361F5ABLL
								/*
								   251 
								 */ ,
	0xFFED95D8F1EA02A2LL		/*
								   252 
								 */ , 0xE72B3BD61464D43DLL
								/*
								   253 
								 */ ,
	0xA6300F170BDC4820LL		/*
								   254 
								 */ , 0xEBC18760ED78A77ALL
								/*
								   255 
								 */ ,
	0xE6A6BE5A05A12138LL		/*
								   256 
								 */ , 0xB5A122A5B4F87C98LL
								/*
								   257 
								 */ ,
	0x563C6089140B6990LL		/*
								   258 
								 */ , 0x4C46CB2E391F5DD5LL
								/*
								   259 
								 */ ,
	0xD932ADDBC9B79434LL		/*
								   260 
								 */ , 0x08EA70E42015AFF5LL
								/*
								   261 
								 */ ,
	0xD765A6673E478CF1LL		/*
								   262 
								 */ , 0xC4FB757EAB278D99LL
								/*
								   263 
								 */ ,
	0xDF11C6862D6E0692LL		/*
								   264 
								 */ , 0xDDEB84F10D7F3B16LL
								/*
								   265 
								 */ ,
	0x6F2EF604A665EA04LL		/*
								   266 
								 */ , 0x4A8E0F0FF0E0DFB3LL
								/*
								   267 
								 */ ,
	0xA5EDEEF83DBCBA51LL		/*
								   268 
								 */ , 0xFC4F0A2A0EA4371ELL
								/*
								   269 
								 */ ,
	0xE83E1DA85CB38429LL		/*
								   270 
								 */ , 0xDC8FF882BA1B1CE2LL
								/*
								   271 
								 */ ,
	0xCD45505E8353E80DLL		/*
								   272 
								 */ , 0x18D19A00D4DB0717LL
								/*
								   273 
								 */ ,
	0x34A0CFEDA5F38101LL		/*
								   274 
								 */ , 0x0BE77E518887CAF2LL
								/*
								   275 
								 */ ,
	0x1E341438B3C45136LL		/*
								   276 
								 */ , 0xE05797F49089CCF9LL
								/*
								   277 
								 */ ,
	0xFFD23F9DF2591D14LL		/*
								   278 
								 */ , 0x543DDA228595C5CDLL
								/*
								   279 
								 */ ,
	0x661F81FD99052A33LL		/*
								   280 
								 */ , 0x8736E641DB0F7B76LL
								/*
								   281 
								 */ ,
	0x15227725418E5307LL		/*
								   282 
								 */ , 0xE25F7F46162EB2FALL
								/*
								   283 
								 */ ,
	0x48A8B2126C13D9FELL		/*
								   284 
								 */ , 0xAFDC541792E76EEALL
								/*
								   285 
								 */ ,
	0x03D912BFC6D1898FLL		/*
								   286 
								 */ , 0x31B1AAFA1B83F51BLL
								/*
								   287 
								 */ ,
	0xF1AC2796E42AB7D9LL		/*
								   288 
								 */ , 0x40A3A7D7FCD2EBACLL
								/*
								   289 
								 */ ,
	0x1056136D0AFBBCC5LL		/*
								   290 
								 */ , 0x7889E1DD9A6D0C85LL
								/*
								   291 
								 */ ,
	0xD33525782A7974AALL		/*
								   292 
								 */ , 0xA7E25D09078AC09BLL
								/*
								   293 
								 */ ,
	0xBD4138B3EAC6EDD0LL		/*
								   294 
								 */ , 0x920ABFBE71EB9E70LL
								/*
								   295 
								 */ ,
	0xA2A5D0F54FC2625CLL		/*
								   296 
								 */ , 0xC054E36B0B1290A3LL
								/*
								   297 
								 */ ,
	0xF6DD59FF62FE932BLL		/*
								   298 
								 */ , 0x3537354511A8AC7DLL
								/*
								   299 
								 */ ,
	0xCA845E9172FADCD4LL		/*
								   300 
								 */ , 0x84F82B60329D20DCLL
								/*
								   301 
								 */ ,
	0x79C62CE1CD672F18LL		/*
								   302 
								 */ , 0x8B09A2ADD124642CLL
								/*
								   303 
								 */ ,
	0xD0C1E96A19D9E726LL		/*
								   304 
								 */ , 0x5A786A9B4BA9500CLL
								/*
								   305 
								 */ ,
	0x0E020336634C43F3LL		/*
								   306 
								 */ , 0xC17B474AEB66D822LL
								/*
								   307 
								 */ ,
	0x6A731AE3EC9BAAC2LL		/*
								   308 
								 */ , 0x8226667AE0840258LL
								/*
								   309 
								 */ ,
	0x67D4567691CAECA5LL		/*
								   310 
								 */ , 0x1D94155C4875ADB5LL
								/*
								   311 
								 */ ,
	0x6D00FD985B813FDFLL		/*
								   312 
								 */ , 0x51286EFCB774CD06LL
								/*
								   313 
								 */ ,
	0x5E8834471FA744AFLL		/*
								   314 
								 */ , 0xF72CA0AEE761AE2ELL
								/*
								   315 
								 */ ,
	0xBE40E4CDAEE8E09ALL		/*
								   316 
								 */ , 0xE9970BBB5118F665LL
								/*
								   317 
								 */ ,
	0x726E4BEB33DF1964LL		/*
								   318 
								 */ , 0x703B000729199762LL
								/*
								   319 
								 */ ,
	0x4631D816F5EF30A7LL		/*
								   320 
								 */ , 0xB880B5B51504A6BELL
								/*
								   321 
								 */ ,
	0x641793C37ED84B6CLL		/*
								   322 
								 */ , 0x7B21ED77F6E97D96LL
								/*
								   323 
								 */ ,
	0x776306312EF96B73LL		/*
								   324 
								 */ , 0xAE528948E86FF3F4LL
								/*
								   325 
								 */ ,
	0x53DBD7F286A3F8F8LL		/*
								   326 
								 */ , 0x16CADCE74CFC1063LL
								/*
								   327 
								 */ ,
	0x005C19BDFA52C6DDLL		/*
								   328 
								 */ , 0x68868F5D64D46AD3LL
								/*
								   329 
								 */ ,
	0x3A9D512CCF1E186ALL		/*
								   330 
								 */ , 0x367E62C2385660AELL
								/*
								   331 
								 */ ,
	0xE359E7EA77DCB1D7LL		/*
								   332 
								 */ , 0x526C0773749ABE6ELL
								/*
								   333 
								 */ ,
	0x735AE5F9D09F734BLL		/*
								   334 
								 */ , 0x493FC7CC8A558BA8LL
								/*
								   335 
								 */ ,
	0xB0B9C1533041AB45LL		/*
								   336 
								 */ , 0x321958BA470A59BDLL
								/*
								   337 
								 */ ,
	0x852DB00B5F46C393LL		/*
								   338 
								 */ , 0x91209B2BD336B0E5LL
								/*
								   339 
								 */ ,
	0x6E604F7D659EF19FLL		/*
								   340 
								 */ , 0xB99A8AE2782CCB24LL
								/*
								   341 
								 */ ,
	0xCCF52AB6C814C4C7LL		/*
								   342 
								 */ , 0x4727D9AFBE11727BLL
								/*
								   343 
								 */ ,
	0x7E950D0C0121B34DLL		/*
								   344 
								 */ , 0x756F435670AD471FLL
								/*
								   345 
								 */ ,
	0xF5ADD442615A6849LL		/*
								   346 
								 */ , 0x4E87E09980B9957ALL
								/*
								   347 
								 */ ,
	0x2ACFA1DF50AEE355LL		/*
								   348 
								 */ , 0xD898263AFD2FD556LL
								/*
								   349 
								 */ ,
	0xC8F4924DD80C8FD6LL		/*
								   350 
								 */ , 0xCF99CA3D754A173ALL
								/*
								   351 
								 */ ,
	0xFE477BACAF91BF3CLL		/*
								   352 
								 */ , 0xED5371F6D690C12DLL
								/*
								   353 
								 */ ,
	0x831A5C285E687094LL		/*
								   354 
								 */ , 0xC5D3C90A3708A0A4LL
								/*
								   355 
								 */ ,
	0x0F7F903717D06580LL		/*
								   356 
								 */ , 0x19F9BB13B8FDF27FLL
								/*
								   357 
								 */ ,
	0xB1BD6F1B4D502843LL		/*
								   358 
								 */ , 0x1C761BA38FFF4012LL
								/*
								   359 
								 */ ,
	0x0D1530C4E2E21F3BLL		/*
								   360 
								 */ , 0x8943CE69A7372C8ALL
								/*
								   361 
								 */ ,
	0xE5184E11FEB5CE66LL		/*
								   362 
								 */ , 0x618BDB80BD736621LL
								/*
								   363 
								 */ ,
	0x7D29BAD68B574D0BLL		/*
								   364 
								 */ , 0x81BB613E25E6FE5BLL
								/*
								   365 
								 */ ,
	0x071C9C10BC07913FLL		/*
								   366 
								 */ , 0xC7BEEB7909AC2D97LL
								/*
								   367 
								 */ ,
	0xC3E58D353BC5D757LL		/*
								   368 
								 */ , 0xEB017892F38F61E8LL
								/*
								   369 
								 */ ,
	0xD4EFFB9C9B1CC21ALL		/*
								   370 
								 */ , 0x99727D26F494F7ABLL
								/*
								   371 
								 */ ,
	0xA3E063A2956B3E03LL		/*
								   372 
								 */ , 0x9D4A8B9A4AA09C30LL
								/*
								   373 
								 */ ,
	0x3F6AB7D500090FB4LL		/*
								   374 
								 */ , 0x9CC0F2A057268AC0LL
								/*
								   375 
								 */ ,
	0x3DEE9D2DEDBF42D1LL		/*
								   376 
								 */ , 0x330F49C87960A972LL
								/*
								   377 
								 */ ,
	0xC6B2720287421B41LL		/*
								   378 
								 */ , 0x0AC59EC07C00369CLL
								/*
								   379 
								 */ ,
	0xEF4EAC49CB353425LL		/*
								   380 
								 */ , 0xF450244EEF0129D8LL
								/*
								   381 
								 */ ,
	0x8ACC46E5CAF4DEB6LL		/*
								   382 
								 */ , 0x2FFEAB63989263F7LL
								/*
								   383 
								 */ ,
	0x8F7CB9FE5D7A4578LL		/*
								   384 
								 */ , 0x5BD8F7644E634635LL
								/*
								   385 
								 */ ,
	0x427A7315BF2DC900LL		/*
								   386 
								 */ , 0x17D0C4AA2125261CLL
								/*
								   387 
								 */ ,
	0x3992486C93518E50LL		/*
								   388 
								 */ , 0xB4CBFEE0A2D7D4C3LL
								/*
								   389 
								 */ ,
	0x7C75D6202C5DDD8DLL		/*
								   390 
								 */ , 0xDBC295D8E35B6C61LL
								/*
								   391 
								 */ ,
	0x60B369D302032B19LL		/*
								   392 
								 */ , 0xCE42685FDCE44132LL
								/*
								   393 
								 */ ,
	0x06F3DDB9DDF65610LL		/*
								   394 
								 */ , 0x8EA4D21DB5E148F0LL
								/*
								   395 
								 */ ,
	0x20B0FCE62FCD496FLL		/*
								   396 
								 */ , 0x2C1B912358B0EE31LL
								/*
								   397 
								 */ ,
	0xB28317B818F5A308LL		/*
								   398 
								 */ , 0xA89C1E189CA6D2CFLL
								/*
								   399 
								 */ ,
	0x0C6B18576AAADBC8LL		/*
								   400 
								 */ , 0xB65DEAA91299FAE3LL
								/*
								   401 
								 */ ,
	0xFB2B794B7F1027E7LL		/*
								   402 
								 */ , 0x04E4317F443B5BEBLL
								/*
								   403 
								 */ ,
	0x4B852D325939D0A6LL		/*
								   404 
								 */ , 0xD5AE6BEEFB207FFCLL
								/*
								   405 
								 */ ,
	0x309682B281C7D374LL		/*
								   406 
								 */ , 0xBAE309A194C3B475LL
								/*
								   407 
								 */ ,
	0x8CC3F97B13B49F05LL		/*
								   408 
								 */ , 0x98A9422FF8293967LL
								/*
								   409 
								 */ ,
	0x244B16B01076FF7CLL		/*
								   410 
								 */ , 0xF8BF571C663D67EELL
								/*
								   411 
								 */ ,
	0x1F0D6758EEE30DA1LL		/*
								   412 
								 */ , 0xC9B611D97ADEB9B7LL
								/*
								   413 
								 */ ,
	0xB7AFD5887B6C57A2LL		/*
								   414 
								 */ , 0x6290AE846B984FE1LL
								/*
								   415 
								 */ ,
	0x94DF4CDEACC1A5FDLL		/*
								   416 
								 */ , 0x058A5BD1C5483AFFLL
								/*
								   417 
								 */ ,
	0x63166CC142BA3C37LL		/*
								   418 
								 */ , 0x8DB8526EB2F76F40LL
								/*
								   419 
								 */ ,
	0xE10880036F0D6D4ELL		/*
								   420 
								 */ , 0x9E0523C9971D311DLL
								/*
								   421 
								 */ ,
	0x45EC2824CC7CD691LL		/*
								   422 
								 */ , 0x575B8359E62382C9LL
								/*
								   423 
								 */ ,
	0xFA9E400DC4889995LL		/*
								   424 
								 */ , 0xD1823ECB45721568LL
								/*
								   425 
								 */ ,
	0xDAFD983B8206082FLL		/*
								   426 
								 */ , 0xAA7D29082386A8CBLL
								/*
								   427 
								 */ ,
	0x269FCD4403B87588LL		/*
								   428 
								 */ , 0x1B91F5F728BDD1E0LL
								/*
								   429 
								 */ ,
	0xE4669F39040201F6LL		/*
								   430 
								 */ , 0x7A1D7C218CF04ADELL
								/*
								   431 
								 */ ,
	0x65623C29D79CE5CELL		/*
								   432 
								 */ , 0x2368449096C00BB1LL
								/*
								   433 
								 */ ,
	0xAB9BF1879DA503BALL		/*
								   434 
								 */ , 0xBC23ECB1A458058ELL
								/*
								   435 
								 */ ,
	0x9A58DF01BB401ECCLL		/*
								   436 
								 */ , 0xA070E868A85F143DLL
								/*
								   437 
								 */ ,
	0x4FF188307DF2239ELL		/*
								   438 
								 */ , 0x14D565B41A641183LL
								/*
								   439 
								 */ ,
	0xEE13337452701602LL		/*
								   440 
								 */ , 0x950E3DCF3F285E09LL
								/*
								   441 
								 */ ,
	0x59930254B9C80953LL		/*
								   442 
								 */ , 0x3BF299408930DA6DLL
								/*
								   443 
								 */ ,
	0xA955943F53691387LL		/*
								   444 
								 */ , 0xA15EDECAA9CB8784LL
								/*
								   445 
								 */ ,
	0x29142127352BE9A0LL		/*
								   446 
								 */ , 0x76F0371FFF4E7AFBLL
								/*
								   447 
								 */ ,
	0x0239F450274F2228LL		/*
								   448 
								 */ , 0xBB073AF01D5E868BLL
								/*
								   449 
								 */ ,
	0xBFC80571C10E96C1LL		/*
								   450 
								 */ , 0xD267088568222E23LL
								/*
								   451 
								 */ ,
	0x9671A3D48E80B5B0LL		/*
								   452 
								 */ , 0x55B5D38AE193BB81LL
								/*
								   453 
								 */ ,
	0x693AE2D0A18B04B8LL		/*
								   454 
								 */ , 0x5C48B4ECADD5335FLL
								/*
								   455 
								 */ ,
	0xFD743B194916A1CALL		/*
								   456 
								 */ , 0x2577018134BE98C4LL
								/*
								   457 
								 */ ,
	0xE77987E83C54A4ADLL		/*
								   458 
								 */ , 0x28E11014DA33E1B9LL
								/*
								   459 
								 */ ,
	0x270CC59E226AA213LL		/*
								   460 
								 */ , 0x71495F756D1A5F60LL
								/*
								   461 
								 */ ,
	0x9BE853FB60AFEF77LL		/*
								   462 
								 */ , 0xADC786A7F7443DBFLL
								/*
								   463 
								 */ ,
	0x0904456173B29A82LL		/*
								   464 
								 */ , 0x58BC7A66C232BD5ELL
								/*
								   465 
								 */ ,
	0xF306558C673AC8B2LL		/*
								   466 
								 */ , 0x41F639C6B6C9772ALL
								/*
								   467 
								 */ ,
	0x216DEFE99FDA35DALL		/*
								   468 
								 */ , 0x11640CC71C7BE615LL
								/*
								   469 
								 */ ,
	0x93C43694565C5527LL		/*
								   470 
								 */ , 0xEA038E6246777839LL
								/*
								   471 
								 */ ,
	0xF9ABF3CE5A3E2469LL		/*
								   472 
								 */ , 0x741E768D0FD312D2LL
								/*
								   473 
								 */ ,
	0x0144B883CED652C6LL		/*
								   474 
								 */ , 0xC20B5A5BA33F8552LL
								/*
								   475 
								 */ ,
	0x1AE69633C3435A9DLL		/*
								   476 
								 */ , 0x97A28CA4088CFDECLL
								/*
								   477 
								 */ ,
	0x8824A43C1E96F420LL		/*
								   478 
								 */ , 0x37612FA66EEEA746LL
								/*
								   479 
								 */ ,
	0x6B4CB165F9CF0E5ALL		/*
								   480 
								 */ , 0x43AA1C06A0ABFB4ALL
								/*
								   481 
								 */ ,
	0x7F4DC26FF162796BLL		/*
								   482 
								 */ , 0x6CBACC8E54ED9B0FLL
								/*
								   483 
								 */ ,
	0xA6B7FFEFD2BB253ELL		/*
								   484 
								 */ , 0x2E25BC95B0A29D4FLL
								/*
								   485 
								 */ ,
	0x86D6A58BDEF1388CLL		/*
								   486 
								 */ , 0xDED74AC576B6F054LL
								/*
								   487 
								 */ ,
	0x8030BDBC2B45805DLL		/*
								   488 
								 */ , 0x3C81AF70E94D9289LL
								/*
								   489 
								 */ ,
	0x3EFF6DDA9E3100DBLL		/*
								   490 
								 */ , 0xB38DC39FDFCC8847LL
								/*
								   491 
								 */ ,
	0x123885528D17B87ELL		/*
								   492 
								 */ , 0xF2DA0ED240B1B642LL
								/*
								   493 
								 */ ,
	0x44CEFADCD54BF9A9LL		/*
								   494 
								 */ , 0x1312200E433C7EE6LL
								/*
								   495 
								 */ ,
	0x9FFCC84F3A78C748LL		/*
								   496 
								 */ , 0xF0CD1F72248576BBLL
								/*
								   497 
								 */ ,
	0xEC6974053638CFE4LL		/*
								   498 
								 */ , 0x2BA7B67C0CEC4E4CLL
								/*
								   499 
								 */ ,
	0xAC2F4DF3E5CE32EDLL		/*
								   500 
								 */ , 0xCB33D14326EA4C11LL
								/*
								   501 
								 */ ,
	0xA4E9044CC77E58BCLL		/*
								   502 
								 */ , 0x5F513293D934FCEFLL
								/*
								   503 
								 */ ,
	0x5DC9645506E55444LL		/*
								   504 
								 */ , 0x50DE418F317DE40ALL
								/*
								   505 
								 */ ,
	0x388CB31A69DDE259LL		/*
								   506 
								 */ , 0x2DB4A83455820A86LL
								/*
								   507 
								 */ ,
	0x9010A91E84711AE9LL		/*
								   508 
								 */ , 0x4DF7F0B7B1498371LL
								/*
								   509 
								 */ ,
	0xD62A2EABC0977179LL		/*
								   510 
								 */ , 0x22FAC097AA8D5C0ELL
								/*
								   511 
								 */ ,
	0xF49FCC2FF1DAF39BLL		/*
								   512 
								 */ , 0x487FD5C66FF29281LL
								/*
								   513 
								 */ ,
	0xE8A30667FCDCA83FLL		/*
								   514 
								 */ , 0x2C9B4BE3D2FCCE63LL
								/*
								   515 
								 */ ,
	0xDA3FF74B93FBBBC2LL		/*
								   516 
								 */ , 0x2FA165D2FE70BA66LL
								/*
								   517 
								 */ ,
	0xA103E279970E93D4LL		/*
								   518 
								 */ , 0xBECDEC77B0E45E71LL
								/*
								   519 
								 */ ,
	0xCFB41E723985E497LL		/*
								   520 
								 */ , 0xB70AAA025EF75017LL
								/*
								   521 
								 */ ,
	0xD42309F03840B8E0LL		/*
								   522 
								 */ , 0x8EFC1AD035898579LL
								/*
								   523 
								 */ ,
	0x96C6920BE2B2ABC5LL		/*
								   524 
								 */ , 0x66AF4163375A9172LL
								/*
								   525 
								 */ ,
	0x2174ABDCCA7127FBLL		/*
								   526 
								 */ , 0xB33CCEA64A72FF41LL
								/*
								   527 
								 */ ,
	0xF04A4933083066A5LL		/*
								   528 
								 */ , 0x8D970ACDD7289AF5LL
								/*
								   529 
								 */ ,
	0x8F96E8E031C8C25ELL		/*
								   530 
								 */ , 0xF3FEC02276875D47LL
								/*
								   531 
								 */ ,
	0xEC7BF310056190DDLL		/*
								   532 
								 */ , 0xF5ADB0AEBB0F1491LL
								/*
								   533 
								 */ ,
	0x9B50F8850FD58892LL		/*
								   534 
								 */ , 0x4975488358B74DE8LL
								/*
								   535 
								 */ ,
	0xA3354FF691531C61LL		/*
								   536 
								 */ , 0x0702BBE481D2C6EELL
								/*
								   537 
								 */ ,
	0x89FB24057DEDED98LL		/*
								   538 
								 */ , 0xAC3075138596E902LL
								/*
								   539 
								 */ ,
	0x1D2D3580172772EDLL		/*
								   540 
								 */ , 0xEB738FC28E6BC30DLL
								/*
								   541 
								 */ ,
	0x5854EF8F63044326LL		/*
								   542 
								 */ , 0x9E5C52325ADD3BBELL
								/*
								   543 
								 */ ,
	0x90AA53CF325C4623LL		/*
								   544 
								 */ , 0xC1D24D51349DD067LL
								/*
								   545 
								 */ ,
	0x2051CFEEA69EA624LL		/*
								   546 
								 */ , 0x13220F0A862E7E4FLL
								/*
								   547 
								 */ ,
	0xCE39399404E04864LL		/*
								   548 
								 */ , 0xD9C42CA47086FCB7LL
								/*
								   549 
								 */ ,
	0x685AD2238A03E7CCLL		/*
								   550 
								 */ , 0x066484B2AB2FF1DBLL
								/*
								   551 
								 */ ,
	0xFE9D5D70EFBF79ECLL		/*
								   552 
								 */ , 0x5B13B9DD9C481854LL
								/*
								   553 
								 */ ,
	0x15F0D475ED1509ADLL		/*
								   554 
								 */ , 0x0BEBCD060EC79851LL
								/*
								   555 
								 */ ,
	0xD58C6791183AB7F8LL		/*
								   556 
								 */ , 0xD1187C5052F3EEE4LL
								/*
								   557 
								 */ ,
	0xC95D1192E54E82FFLL		/*
								   558 
								 */ , 0x86EEA14CB9AC6CA2LL
								/*
								   559 
								 */ ,
	0x3485BEB153677D5DLL		/*
								   560 
								 */ , 0xDD191D781F8C492ALL
								/*
								   561 
								 */ ,
	0xF60866BAA784EBF9LL		/*
								   562 
								 */ , 0x518F643BA2D08C74LL
								/*
								   563 
								 */ ,
	0x8852E956E1087C22LL		/*
								   564 
								 */ , 0xA768CB8DC410AE8DLL
								/*
								   565 
								 */ ,
	0x38047726BFEC8E1ALL		/*
								   566 
								 */ , 0xA67738B4CD3B45AALL
								/*
								   567 
								 */ ,
	0xAD16691CEC0DDE19LL		/*
								   568 
								 */ , 0xC6D4319380462E07LL
								/*
								   569 
								 */ ,
	0xC5A5876D0BA61938LL		/*
								   570 
								 */ , 0x16B9FA1FA58FD840LL
								/*
								   571 
								 */ ,
	0x188AB1173CA74F18LL		/*
								   572 
								 */ , 0xABDA2F98C99C021FLL
								/*
								   573 
								 */ ,
	0x3E0580AB134AE816LL		/*
								   574 
								 */ , 0x5F3B05B773645ABBLL
								/*
								   575 
								 */ ,
	0x2501A2BE5575F2F6LL		/*
								   576 
								 */ , 0x1B2F74004E7E8BA9LL
								/*
								   577 
								 */ ,
	0x1CD7580371E8D953LL		/*
								   578 
								 */ , 0x7F6ED89562764E30LL
								/*
								   579 
								 */ ,
	0xB15926FF596F003DLL		/*
								   580 
								 */ , 0x9F65293DA8C5D6B9LL
								/*
								   581 
								 */ ,
	0x6ECEF04DD690F84CLL		/*
								   582 
								 */ , 0x4782275FFF33AF88LL
								/*
								   583 
								 */ ,
	0xE41433083F820801LL		/*
								   584 
								 */ , 0xFD0DFE409A1AF9B5LL
								/*
								   585 
								 */ ,
	0x4325A3342CDB396BLL		/*
								   586 
								 */ , 0x8AE77E62B301B252LL
								/*
								   587 
								 */ ,
	0xC36F9E9F6655615ALL		/*
								   588 
								 */ , 0x85455A2D92D32C09LL
								/*
								   589 
								 */ ,
	0xF2C7DEA949477485LL		/*
								   590 
								 */ , 0x63CFB4C133A39EBALL
								/*
								   591 
								 */ ,
	0x83B040CC6EBC5462LL		/*
								   592 
								 */ , 0x3B9454C8FDB326B0LL
								/*
								   593 
								 */ ,
	0x56F56A9E87FFD78CLL		/*
								   594 
								 */ , 0x2DC2940D99F42BC6LL
								/*
								   595 
								 */ ,
	0x98F7DF096B096E2DLL		/*
								   596 
								 */ , 0x19A6E01E3AD852BFLL
								/*
								   597 
								 */ ,
	0x42A99CCBDBD4B40BLL		/*
								   598 
								 */ , 0xA59998AF45E9C559LL
								/*
								   599 
								 */ ,
	0x366295E807D93186LL		/*
								   600 
								 */ , 0x6B48181BFAA1F773LL
								/*
								   601 
								 */ ,
	0x1FEC57E2157A0A1DLL		/*
								   602 
								 */ , 0x4667446AF6201AD5LL
								/*
								   603 
								 */ ,
	0xE615EBCACFB0F075LL		/*
								   604 
								 */ , 0xB8F31F4F68290778LL
								/*
								   605 
								 */ ,
	0x22713ED6CE22D11ELL		/*
								   606 
								 */ , 0x3057C1A72EC3C93BLL
								/*
								   607 
								 */ ,
	0xCB46ACC37C3F1F2FLL		/*
								   608 
								 */ , 0xDBB893FD02AAF50ELL
								/*
								   609 
								 */ ,
	0x331FD92E600B9FCFLL		/*
								   610 
								 */ , 0xA498F96148EA3AD6LL
								/*
								   611 
								 */ ,
	0xA8D8426E8B6A83EALL		/*
								   612 
								 */ , 0xA089B274B7735CDCLL
								/*
								   613 
								 */ ,
	0x87F6B3731E524A11LL		/*
								   614 
								 */ , 0x118808E5CBC96749LL
								/*
								   615 
								 */ ,
	0x9906E4C7B19BD394LL		/*
								   616 
								 */ , 0xAFED7F7E9B24A20CLL
								/*
								   617 
								 */ ,
	0x6509EADEEB3644A7LL		/*
								   618 
								 */ , 0x6C1EF1D3E8EF0EDELL
								/*
								   619 
								 */ ,
	0xB9C97D43E9798FB4LL		/*
								   620 
								 */ , 0xA2F2D784740C28A3LL
								/*
								   621 
								 */ ,
	0x7B8496476197566FLL		/*
								   622 
								 */ , 0x7A5BE3E6B65F069DLL
								/*
								   623 
								 */ ,
	0xF96330ED78BE6F10LL		/*
								   624 
								 */ , 0xEEE60DE77A076A15LL
								/*
								   625 
								 */ ,
	0x2B4BEE4AA08B9BD0LL		/*
								   626 
								 */ , 0x6A56A63EC7B8894ELL
								/*
								   627 
								 */ ,
	0x02121359BA34FEF4LL		/*
								   628 
								 */ , 0x4CBF99F8283703FCLL
								/*
								   629 
								 */ ,
	0x398071350CAF30C8LL		/*
								   630 
								 */ , 0xD0A77A89F017687ALL
								/*
								   631 
								 */ ,
	0xF1C1A9EB9E423569LL		/*
								   632 
								 */ , 0x8C7976282DEE8199LL
								/*
								   633 
								 */ ,
	0x5D1737A5DD1F7ABDLL		/*
								   634 
								 */ , 0x4F53433C09A9FA80LL
								/*
								   635 
								 */ ,
	0xFA8B0C53DF7CA1D9LL		/*
								   636 
								 */ , 0x3FD9DCBC886CCB77LL
								/*
								   637 
								 */ ,
	0xC040917CA91B4720LL		/*
								   638 
								 */ , 0x7DD00142F9D1DCDFLL
								/*
								   639 
								 */ ,
	0x8476FC1D4F387B58LL		/*
								   640 
								 */ , 0x23F8E7C5F3316503LL
								/*
								   641 
								 */ ,
	0x032A2244E7E37339LL		/*
								   642 
								 */ , 0x5C87A5D750F5A74BLL
								/*
								   643 
								 */ ,
	0x082B4CC43698992ELL		/*
								   644 
								 */ , 0xDF917BECB858F63CLL
								/*
								   645 
								 */ ,
	0x3270B8FC5BF86DDALL		/*
								   646 
								 */ , 0x10AE72BB29B5DD76LL
								/*
								   647 
								 */ ,
	0x576AC94E7700362BLL		/*
								   648 
								 */ , 0x1AD112DAC61EFB8FLL
								/*
								   649 
								 */ ,
	0x691BC30EC5FAA427LL		/*
								   650 
								 */ , 0xFF246311CC327143LL
								/*
								   651 
								 */ ,
	0x3142368E30E53206LL		/*
								   652 
								 */ , 0x71380E31E02CA396LL
								/*
								   653 
								 */ ,
	0x958D5C960AAD76F1LL		/*
								   654 
								 */ , 0xF8D6F430C16DA536LL
								/*
								   655 
								 */ ,
	0xC8FFD13F1BE7E1D2LL		/*
								   656 
								 */ , 0x7578AE66004DDBE1LL
								/*
								   657 
								 */ ,
	0x05833F01067BE646LL		/*
								   658 
								 */ , 0xBB34B5AD3BFE586DLL
								/*
								   659 
								 */ ,
	0x095F34C9A12B97F0LL		/*
								   660 
								 */ , 0x247AB64525D60CA8LL
								/*
								   661 
								 */ ,
	0xDCDBC6F3017477D1LL		/*
								   662 
								 */ , 0x4A2E14D4DECAD24DLL
								/*
								   663 
								 */ ,
	0xBDB5E6D9BE0A1EEBLL		/*
								   664 
								 */ , 0x2A7E70F7794301ABLL
								/*
								   665 
								 */ ,
	0xDEF42D8A270540FDLL		/*
								   666 
								 */ , 0x01078EC0A34C22C1LL
								/*
								   667 
								 */ ,
	0xE5DE511AF4C16387LL		/*
								   668 
								 */ , 0x7EBB3A52BD9A330ALL
								/*
								   669 
								 */ ,
	0x77697857AA7D6435LL		/*
								   670 
								 */ , 0x004E831603AE4C32LL
								/*
								   671 
								 */ ,
	0xE7A21020AD78E312LL		/*
								   672 
								 */ , 0x9D41A70C6AB420F2LL
								/*
								   673 
								 */ ,
	0x28E06C18EA1141E6LL		/*
								   674 
								 */ , 0xD2B28CBD984F6B28LL
								/*
								   675 
								 */ ,
	0x26B75F6C446E9D83LL		/*
								   676 
								 */ , 0xBA47568C4D418D7FLL
								/*
								   677 
								 */ ,
	0xD80BADBFE6183D8ELL		/*
								   678 
								 */ , 0x0E206D7F5F166044LL
								/*
								   679 
								 */ ,
	0xE258A43911CBCA3ELL		/*
								   680 
								 */ , 0x723A1746B21DC0BCLL
								/*
								   681 
								 */ ,
	0xC7CAA854F5D7CDD3LL		/*
								   682 
								 */ , 0x7CAC32883D261D9CLL
								/*
								   683 
								 */ ,
	0x7690C26423BA942CLL		/*
								   684 
								 */ , 0x17E55524478042B8LL
								/*
								   685 
								 */ ,
	0xE0BE477656A2389FLL		/*
								   686 
								 */ , 0x4D289B5E67AB2DA0LL
								/*
								   687 
								 */ ,
	0x44862B9C8FBBFD31LL		/*
								   688 
								 */ , 0xB47CC8049D141365LL
								/*
								   689 
								 */ ,
	0x822C1B362B91C793LL		/*
								   690 
								 */ , 0x4EB14655FB13DFD8LL
								/*
								   691 
								 */ ,
	0x1ECBBA0714E2A97BLL		/*
								   692 
								 */ , 0x6143459D5CDE5F14LL
								/*
								   693 
								 */ ,
	0x53A8FBF1D5F0AC89LL		/*
								   694 
								 */ , 0x97EA04D81C5E5B00LL
								/*
								   695 
								 */ ,
	0x622181A8D4FDB3F3LL		/*
								   696 
								 */ , 0xE9BCD341572A1208LL
								/*
								   697 
								 */ ,
	0x1411258643CCE58ALL		/*
								   698 
								 */ , 0x9144C5FEA4C6E0A4LL
								/*
								   699 
								 */ ,
	0x0D33D06565CF620FLL		/*
								   700 
								 */ , 0x54A48D489F219CA1LL
								/*
								   701 
								 */ ,
	0xC43E5EAC6D63C821LL		/*
								   702 
								 */ , 0xA9728B3A72770DAFLL
								/*
								   703 
								 */ ,
	0xD7934E7B20DF87EFLL		/*
								   704 
								 */ , 0xE35503B61A3E86E5LL
								/*
								   705 
								 */ ,
	0xCAE321FBC819D504LL		/*
								   706 
								 */ , 0x129A50B3AC60BFA6LL
								/*
								   707 
								 */ ,
	0xCD5E68EA7E9FB6C3LL		/*
								   708 
								 */ , 0xB01C90199483B1C7LL
								/*
								   709 
								 */ ,
	0x3DE93CD5C295376CLL		/*
								   710 
								 */ , 0xAED52EDF2AB9AD13LL
								/*
								   711 
								 */ ,
	0x2E60F512C0A07884LL		/*
								   712 
								 */ , 0xBC3D86A3E36210C9LL
								/*
								   713 
								 */ ,
	0x35269D9B163951CELL		/*
								   714 
								 */ , 0x0C7D6E2AD0CDB5FALL
								/*
								   715 
								 */ ,
	0x59E86297D87F5733LL		/*
								   716 
								 */ , 0x298EF221898DB0E7LL
								/*
								   717 
								 */ ,
	0x55000029D1A5AA7ELL		/*
								   718 
								 */ , 0x8BC08AE1B5061B45LL
								/*
								   719 
								 */ ,
	0xC2C31C2B6C92703ALL		/*
								   720 
								 */ , 0x94CC596BAF25EF42LL
								/*
								   721 
								 */ ,
	0x0A1D73DB22540456LL		/*
								   722 
								 */ , 0x04B6A0F9D9C4179ALL
								/*
								   723 
								 */ ,
	0xEFFDAFA2AE3D3C60LL		/*
								   724 
								 */ , 0xF7C8075BB49496C4LL
								/*
								   725 
								 */ ,
	0x9CC5C7141D1CD4E3LL		/*
								   726 
								 */ , 0x78BD1638218E5534LL
								/*
								   727 
								 */ ,
	0xB2F11568F850246ALL		/*
								   728 
								 */ , 0xEDFABCFA9502BC29LL
								/*
								   729 
								 */ ,
	0x796CE5F2DA23051BLL		/*
								   730 
								 */ , 0xAAE128B0DC93537CLL
								/*
								   731 
								 */ ,
	0x3A493DA0EE4B29AELL		/*
								   732 
								 */ , 0xB5DF6B2C416895D7LL
								/*
								   733 
								 */ ,
	0xFCABBD25122D7F37LL		/*
								   734 
								 */ , 0x70810B58105DC4B1LL
								/*
								   735 
								 */ ,
	0xE10FDD37F7882A90LL		/*
								   736 
								 */ , 0x524DCAB5518A3F5CLL
								/*
								   737 
								 */ ,
	0x3C9E85878451255BLL		/*
								   738 
								 */ , 0x4029828119BD34E2LL
								/*
								   739 
								 */ ,
	0x74A05B6F5D3CECCBLL		/*
								   740 
								 */ , 0xB610021542E13ECALL
								/*
								   741 
								 */ ,
	0x0FF979D12F59E2ACLL		/*
								   742 
								 */ , 0x6037DA27E4F9CC50LL
								/*
								   743 
								 */ ,
	0x5E92975A0DF1847DLL		/*
								   744 
								 */ , 0xD66DE190D3E623FELL
								/*
								   745 
								 */ ,
	0x5032D6B87B568048LL		/*
								   746 
								 */ , 0x9A36B7CE8235216ELL
								/*
								   747 
								 */ ,
	0x80272A7A24F64B4ALL		/*
								   748 
								 */ , 0x93EFED8B8C6916F7LL
								/*
								   749 
								 */ ,
	0x37DDBFF44CCE1555LL		/*
								   750 
								 */ , 0x4B95DB5D4B99BD25LL
								/*
								   751 
								 */ ,
	0x92D3FDA169812FC0LL		/*
								   752 
								 */ , 0xFB1A4A9A90660BB6LL
								/*
								   753 
								 */ ,
	0x730C196946A4B9B2LL		/*
								   754 
								 */ , 0x81E289AA7F49DA68LL
								/*
								   755 
								 */ ,
	0x64669A0F83B1A05FLL		/*
								   756 
								 */ , 0x27B3FF7D9644F48BLL
								/*
								   757 
								 */ ,
	0xCC6B615C8DB675B3LL		/*
								   758 
								 */ , 0x674F20B9BCEBBE95LL
								/*
								   759 
								 */ ,
	0x6F31238275655982LL		/*
								   760 
								 */ , 0x5AE488713E45CF05LL
								/*
								   761 
								 */ ,
	0xBF619F9954C21157LL		/*
								   762 
								 */ , 0xEABAC46040A8EAE9LL
								/*
								   763 
								 */ ,
	0x454C6FE9F2C0C1CDLL		/*
								   764 
								 */ , 0x419CF6496412691CLL
								/*
								   765 
								 */ ,
	0xD3DC3BEF265B0F70LL		/*
								   766 
								 */ , 0x6D0E60F5C3578A9ELL
								/*
								   767 
								 */ ,
	0x5B0E608526323C55LL		/*
								   768 
								 */ , 0x1A46C1A9FA1B59F5LL
								/*
								   769 
								 */ ,
	0xA9E245A17C4C8FFALL		/*
								   770 
								 */ , 0x65CA5159DB2955D7LL
								/*
								   771 
								 */ ,
	0x05DB0A76CE35AFC2LL		/*
								   772 
								 */ , 0x81EAC77EA9113D45LL
								/*
								   773 
								 */ ,
	0x528EF88AB6AC0A0DLL		/*
								   774 
								 */ , 0xA09EA253597BE3FFLL
								/*
								   775 
								 */ ,
	0x430DDFB3AC48CD56LL		/*
								   776 
								 */ , 0xC4B3A67AF45CE46FLL
								/*
								   777 
								 */ ,
	0x4ECECFD8FBE2D05ELL		/*
								   778 
								 */ , 0x3EF56F10B39935F0LL
								/*
								   779 
								 */ ,
	0x0B22D6829CD619C6LL		/*
								   780 
								 */ , 0x17FD460A74DF2069LL
								/*
								   781 
								 */ ,
	0x6CF8CC8E8510ED40LL		/*
								   782 
								 */ , 0xD6C824BF3A6ECAA7LL
								/*
								   783 
								 */ ,
	0x61243D581A817049LL		/*
								   784 
								 */ , 0x048BACB6BBC163A2LL
								/*
								   785 
								 */ ,
	0xD9A38AC27D44CC32LL		/*
								   786 
								 */ , 0x7FDDFF5BAAF410ABLL
								/*
								   787 
								 */ ,
	0xAD6D495AA804824BLL		/*
								   788 
								 */ , 0xE1A6A74F2D8C9F94LL
								/*
								   789 
								 */ ,
	0xD4F7851235DEE8E3LL		/*
								   790 
								 */ , 0xFD4B7F886540D893LL
								/*
								   791 
								 */ ,
	0x247C20042AA4BFDALL		/*
								   792 
								 */ , 0x096EA1C517D1327CLL
								/*
								   793 
								 */ ,
	0xD56966B4361A6685LL		/*
								   794 
								 */ , 0x277DA5C31221057DLL
								/*
								   795 
								 */ ,
	0x94D59893A43ACFF7LL		/*
								   796 
								 */ , 0x64F0C51CCDC02281LL
								/*
								   797 
								 */ ,
	0x3D33BCC4FF6189DBLL		/*
								   798 
								 */ , 0xE005CB184CE66AF1LL
								/*
								   799 
								 */ ,
	0xFF5CCD1D1DB99BEALL		/*
								   800 
								 */ , 0xB0B854A7FE42980FLL
								/*
								   801 
								 */ ,
	0x7BD46A6A718D4B9FLL		/*
								   802 
								 */ , 0xD10FA8CC22A5FD8CLL
								/*
								   803 
								 */ ,
	0xD31484952BE4BD31LL		/*
								   804 
								 */ , 0xC7FA975FCB243847LL
								/*
								   805 
								 */ ,
	0x4886ED1E5846C407LL		/*
								   806 
								 */ , 0x28CDDB791EB70B04LL
								/*
								   807 
								 */ ,
	0xC2B00BE2F573417FLL		/*
								   808 
								 */ , 0x5C9590452180F877LL
								/*
								   809 
								 */ ,
	0x7A6BDDFFF370EB00LL		/*
								   810 
								 */ , 0xCE509E38D6D9D6A4LL
								/*
								   811 
								 */ ,
	0xEBEB0F00647FA702LL		/*
								   812 
								 */ , 0x1DCC06CF76606F06LL
								/*
								   813 
								 */ ,
	0xE4D9F28BA286FF0ALL		/*
								   814 
								 */ , 0xD85A305DC918C262LL
								/*
								   815 
								 */ ,
	0x475B1D8732225F54LL		/*
								   816 
								 */ , 0x2D4FB51668CCB5FELL
								/*
								   817 
								 */ ,
	0xA679B9D9D72BBA20LL		/*
								   818 
								 */ , 0x53841C0D912D43A5LL
								/*
								   819 
								 */ ,
	0x3B7EAA48BF12A4E8LL		/*
								   820 
								 */ , 0x781E0E47F22F1DDFLL
								/*
								   821 
								 */ ,
	0xEFF20CE60AB50973LL		/*
								   822 
								 */ , 0x20D261D19DFFB742LL
								/*
								   823 
								 */ ,
	0x16A12B03062A2E39LL		/*
								   824 
								 */ , 0x1960EB2239650495LL
								/*
								   825 
								 */ ,
	0x251C16FED50EB8B8LL		/*
								   826 
								 */ , 0x9AC0C330F826016ELL
								/*
								   827 
								 */ ,
	0xED152665953E7671LL		/*
								   828 
								 */ , 0x02D63194A6369570LL
								/*
								   829 
								 */ ,
	0x5074F08394B1C987LL		/*
								   830 
								 */ , 0x70BA598C90B25CE1LL
								/*
								   831 
								 */ ,
	0x794A15810B9742F6LL		/*
								   832 
								 */ , 0x0D5925E9FCAF8C6CLL
								/*
								   833 
								 */ ,
	0x3067716CD868744ELL		/*
								   834 
								 */ , 0x910AB077E8D7731BLL
								/*
								   835 
								 */ ,
	0x6A61BBDB5AC42F61LL		/*
								   836 
								 */ , 0x93513EFBF0851567LL
								/*
								   837 
								 */ ,
	0xF494724B9E83E9D5LL		/*
								   838 
								 */ , 0xE887E1985C09648DLL
								/*
								   839 
								 */ ,
	0x34B1D3C675370CFDLL		/*
								   840 
								 */ , 0xDC35E433BC0D255DLL
								/*
								   841 
								 */ ,
	0xD0AAB84234131BE0LL		/*
								   842 
								 */ , 0x08042A50B48B7EAFLL
								/*
								   843 
								 */ ,
	0x9997C4EE44A3AB35LL		/*
								   844 
								 */ , 0x829A7B49201799D0LL
								/*
								   845 
								 */ ,
	0x263B8307B7C54441LL		/*
								   846 
								 */ , 0x752F95F4FD6A6CA6LL
								/*
								   847 
								 */ ,
	0x927217402C08C6E5LL		/*
								   848 
								 */ , 0x2A8AB754A795D9EELL
								/*
								   849 
								 */ ,
	0xA442F7552F72943DLL		/*
								   850 
								 */ , 0x2C31334E19781208LL
								/*
								   851 
								 */ ,
	0x4FA98D7CEAEE6291LL		/*
								   852 
								 */ , 0x55C3862F665DB309LL
								/*
								   853 
								 */ ,
	0xBD0610175D53B1F3LL		/*
								   854 
								 */ , 0x46FE6CB840413F27LL
								/*
								   855 
								 */ ,
	0x3FE03792DF0CFA59LL		/*
								   856 
								 */ , 0xCFE700372EB85E8FLL
								/*
								   857 
								 */ ,
	0xA7BE29E7ADBCE118LL		/*
								   858 
								 */ , 0xE544EE5CDE8431DDLL
								/*
								   859 
								 */ ,
	0x8A781B1B41F1873ELL		/*
								   860 
								 */ , 0xA5C94C78A0D2F0E7LL
								/*
								   861 
								 */ ,
	0x39412E2877B60728LL		/*
								   862 
								 */ , 0xA1265EF3AFC9A62CLL
								/*
								   863 
								 */ ,
	0xBCC2770C6A2506C5LL		/*
								   864 
								 */ , 0x3AB66DD5DCE1CE12LL
								/*
								   865 
								 */ ,
	0xE65499D04A675B37LL		/*
								   866 
								 */ , 0x7D8F523481BFD216LL
								/*
								   867 
								 */ ,
	0x0F6F64FCEC15F389LL		/*
								   868 
								 */ , 0x74EFBE618B5B13C8LL
								/*
								   869 
								 */ ,
	0xACDC82B714273E1DLL		/*
								   870 
								 */ , 0xDD40BFE003199D17LL
								/*
								   871 
								 */ ,
	0x37E99257E7E061F8LL		/*
								   872 
								 */ , 0xFA52626904775AAALL
								/*
								   873 
								 */ ,
	0x8BBBF63A463D56F9LL		/*
								   874 
								 */ , 0xF0013F1543A26E64LL
								/*
								   875 
								 */ ,
	0xA8307E9F879EC898LL		/*
								   876 
								 */ , 0xCC4C27A4150177CCLL
								/*
								   877 
								 */ ,
	0x1B432F2CCA1D3348LL		/*
								   878 
								 */ , 0xDE1D1F8F9F6FA013LL
								/*
								   879 
								 */ ,
	0x606602A047A7DDD6LL		/*
								   880 
								 */ , 0xD237AB64CC1CB2C7LL
								/*
								   881 
								 */ ,
	0x9B938E7225FCD1D3LL		/*
								   882 
								 */ , 0xEC4E03708E0FF476LL
								/*
								   883 
								 */ ,
	0xFEB2FBDA3D03C12DLL		/*
								   884 
								 */ , 0xAE0BCED2EE43889ALL
								/*
								   885 
								 */ ,
	0x22CB8923EBFB4F43LL		/*
								   886 
								 */ , 0x69360D013CF7396DLL
								/*
								   887 
								 */ ,
	0x855E3602D2D4E022LL		/*
								   888 
								 */ , 0x073805BAD01F784CLL
								/*
								   889 
								 */ ,
	0x33E17A133852F546LL		/*
								   890 
								 */ , 0xDF4874058AC7B638LL
								/*
								   891 
								 */ ,
	0xBA92B29C678AA14ALL		/*
								   892 
								 */ , 0x0CE89FC76CFAADCDLL
								/*
								   893 
								 */ ,
	0x5F9D4E0908339E34LL		/*
								   894 
								 */ , 0xF1AFE9291F5923B9LL
								/*
								   895 
								 */ ,
	0x6E3480F60F4A265FLL		/*
								   896 
								 */ , 0xEEBF3A2AB29B841CLL
								/*
								   897 
								 */ ,
	0xE21938A88F91B4ADLL		/*
								   898 
								 */ , 0x57DFEFF845C6D3C3LL
								/*
								   899 
								 */ ,
	0x2F006B0BF62CAAF2LL		/*
								   900 
								 */ , 0x62F479EF6F75EE78LL
								/*
								   901 
								 */ ,
	0x11A55AD41C8916A9LL		/*
								   902 
								 */ , 0xF229D29084FED453LL
								/*
								   903 
								 */ ,
	0x42F1C27B16B000E6LL		/*
								   904 
								 */ , 0x2B1F76749823C074LL
								/*
								   905 
								 */ ,
	0x4B76ECA3C2745360LL		/*
								   906 
								 */ , 0x8C98F463B91691BDLL
								/*
								   907 
								 */ ,
	0x14BCC93CF1ADE66ALL		/*
								   908 
								 */ , 0x8885213E6D458397LL
								/*
								   909 
								 */ ,
	0x8E177DF0274D4711LL		/*
								   910 
								 */ , 0xB49B73B5503F2951LL
								/*
								   911 
								 */ ,
	0x10168168C3F96B6BLL		/*
								   912 
								 */ , 0x0E3D963B63CAB0AELL
								/*
								   913 
								 */ ,
	0x8DFC4B5655A1DB14LL		/*
								   914 
								 */ , 0xF789F1356E14DE5CLL
								/*
								   915 
								 */ ,
	0x683E68AF4E51DAC1LL		/*
								   916 
								 */ , 0xC9A84F9D8D4B0FD9LL
								/*
								   917 
								 */ ,
	0x3691E03F52A0F9D1LL		/*
								   918 
								 */ , 0x5ED86E46E1878E80LL
								/*
								   919 
								 */ ,
	0x3C711A0E99D07150LL		/*
								   920 
								 */ , 0x5A0865B20C4E9310LL
								/*
								   921 
								 */ ,
	0x56FBFC1FE4F0682ELL		/*
								   922 
								 */ , 0xEA8D5DE3105EDF9BLL
								/*
								   923 
								 */ ,
	0x71ABFDB12379187ALL		/*
								   924 
								 */ , 0x2EB99DE1BEE77B9CLL
								/*
								   925 
								 */ ,
	0x21ECC0EA33CF4523LL		/*
								   926 
								 */ , 0x59A4D7521805C7A1LL
								/*
								   927 
								 */ ,
	0x3896F5EB56AE7C72LL		/*
								   928 
								 */ , 0xAA638F3DB18F75DCLL
								/*
								   929 
								 */ ,
	0x9F39358DABE9808ELL		/*
								   930 
								 */ , 0xB7DEFA91C00B72ACLL
								/*
								   931 
								 */ ,
	0x6B5541FD62492D92LL		/*
								   932 
								 */ , 0x6DC6DEE8F92E4D5BLL
								/*
								   933 
								 */ ,
	0x353F57ABC4BEEA7ELL		/*
								   934 
								 */ , 0x735769D6DA5690CELL
								/*
								   935 
								 */ ,
	0x0A234AA642391484LL		/*
								   936 
								 */ , 0xF6F9508028F80D9DLL
								/*
								   937 
								 */ ,
	0xB8E319A27AB3F215LL		/*
								   938 
								 */ , 0x31AD9C1151341A4DLL
								/*
								   939 
								 */ ,
	0x773C22A57BEF5805LL		/*
								   940 
								 */ , 0x45C7561A07968633LL
								/*
								   941 
								 */ ,
	0xF913DA9E249DBE36LL		/*
								   942 
								 */ , 0xDA652D9B78A64C68LL
								/*
								   943 
								 */ ,
	0x4C27A97F3BC334EFLL		/*
								   944 
								 */ , 0x76621220E66B17F4LL
								/*
								   945 
								 */ ,
	0x967743899ACD7D0BLL		/*
								   946 
								 */ , 0xF3EE5BCAE0ED6782LL
								/*
								   947 
								 */ ,
	0x409F753600C879FCLL		/*
								   948 
								 */ , 0x06D09A39B5926DB6LL
								/*
								   949 
								 */ ,
	0x6F83AEB0317AC588LL		/*
								   950 
								 */ , 0x01E6CA4A86381F21LL
								/*
								   951 
								 */ ,
	0x66FF3462D19F3025LL		/*
								   952 
								 */ , 0x72207C24DDFD3BFBLL
								/*
								   953 
								 */ ,
	0x4AF6B6D3E2ECE2EBLL		/*
								   954 
								 */ , 0x9C994DBEC7EA08DELL
								/*
								   955 
								 */ ,
	0x49ACE597B09A8BC4LL		/*
								   956 
								 */ , 0xB38C4766CF0797BALL
								/*
								   957 
								 */ ,
	0x131B9373C57C2A75LL		/*
								   958 
								 */ , 0xB1822CCE61931E58LL
								/*
								   959 
								 */ ,
	0x9D7555B909BA1C0CLL		/*
								   960 
								 */ , 0x127FAFDD937D11D2LL
								/*
								   961 
								 */ ,
	0x29DA3BADC66D92E4LL		/*
								   962 
								 */ , 0xA2C1D57154C2ECBCLL
								/*
								   963 
								 */ ,
	0x58C5134D82F6FE24LL		/*
								   964 
								 */ , 0x1C3AE3515B62274FLL
								/*
								   965 
								 */ ,
	0xE907C82E01CB8126LL		/*
								   966 
								 */ , 0xF8ED091913E37FCBLL
								/*
								   967 
								 */ ,
	0x3249D8F9C80046C9LL		/*
								   968 
								 */ , 0x80CF9BEDE388FB63LL
								/*
								   969 
								 */ ,
	0x1881539A116CF19ELL		/*
								   970 
								 */ , 0x5103F3F76BD52457LL
								/*
								   971 
								 */ ,
	0x15B7E6F5AE47F7A8LL		/*
								   972 
								 */ , 0xDBD7C6DED47E9CCFLL
								/*
								   973 
								 */ ,
	0x44E55C410228BB1ALL		/*
								   974 
								 */ , 0xB647D4255EDB4E99LL
								/*
								   975 
								 */ ,
	0x5D11882BB8AAFC30LL		/*
								   976 
								 */ , 0xF5098BBB29D3212ALL
								/*
								   977 
								 */ ,
	0x8FB5EA14E90296B3LL		/*
								   978 
								 */ , 0x677B942157DD025ALL
								/*
								   979 
								 */ ,
	0xFB58E7C0A390ACB5LL		/*
								   980 
								 */ , 0x89D3674C83BD4A01LL
								/*
								   981 
								 */ ,
	0x9E2DA4DF4BF3B93BLL		/*
								   982 
								 */ , 0xFCC41E328CAB4829LL
								/*
								   983 
								 */ ,
	0x03F38C96BA582C52LL		/*
								   984 
								 */ , 0xCAD1BDBD7FD85DB2LL
								/*
								   985 
								 */ ,
	0xBBB442C16082AE83LL		/*
								   986 
								 */ , 0xB95FE86BA5DA9AB0LL
								/*
								   987 
								 */ ,
	0xB22E04673771A93FLL		/*
								   988 
								 */ , 0x845358C9493152D8LL
								/*
								   989 
								 */ ,
	0xBE2A488697B4541ELL		/*
								   990 
								 */ , 0x95A2DC2DD38E6966LL
								/*
								   991 
								 */ ,
	0xC02C11AC923C852BLL		/*
								   992 
								 */ , 0x2388B1990DF2A87BLL
								/*
								   993 
								 */ ,
	0x7C8008FA1B4F37BELL		/*
								   994 
								 */ , 0x1F70D0C84D54E503LL
								/*
								   995 
								 */ ,
	0x5490ADEC7ECE57D4LL		/*
								   996 
								 */ , 0x002B3C27D9063A3ALL
								/*
								   997 
								 */ ,
	0x7EAEA3848030A2BFLL		/*
								   998 
								 */ , 0xC602326DED2003C0LL
								/*
								   999 
								 */ ,
	0x83A7287D69A94086LL		/*
								   1000 
								 */ , 0xC57A5FCB30F57A8ALL
								/*
								   1001 
								 */ ,
	0xB56844E479EBE779LL		/*
								   1002 
								 */ , 0xA373B40F05DCBCE9LL
								/*
								   1003 
								 */ ,
	0xD71A786E88570EE2LL		/*
								   1004 
								 */ , 0x879CBACDBDE8F6A0LL
								/*
								   1005 
								 */ ,
	0x976AD1BCC164A32FLL		/*
								   1006 
								 */ , 0xAB21E25E9666D78BLL
								/*
								   1007 
								 */ ,
	0x901063AAE5E5C33CLL		/*
								   1008 
								 */ , 0x9818B34448698D90LL
								/*
								   1009 
								 */ ,
	0xE36487AE3E1E8ABBLL		/*
								   1010 
								 */ , 0xAFBDF931893BDCB4LL
								/*
								   1011 
								 */ ,
	0x6345A0DC5FBBD519LL		/*
								   1012 
								 */ , 0x8628FE269B9465CALL
								/*
								   1013 
								 */ ,
	0x1E5D01603F9C51ECLL		/*
								   1014 
								 */ , 0x4DE44006A15049B7LL
								/*
								   1015 
								 */ ,
	0xBF6C70E5F776CBB1LL		/*
								   1016 
								 */ , 0x411218F2EF552BEDLL
								/*
								   1017 
								 */ ,
	0xCB0C0708705A36A3LL		/*
								   1018 
								 */ , 0xE74D14754F986044LL
								/*
								   1019 
								 */ ,
	0xCD56D9430EA8280ELL		/*
								   1020 
								 */ , 0xC12591D7535F5065LL
								/*
								   1021 
								 */ ,
	0xC83223F1720AEF96LL		/*
								   1022 
								 */ , 0xC3A0396F7363A51FLL
								/*
								   1023 
								 */ };


#else

word32 table[4*256][2] = {
    0xF7E90C5E, 0x02AAB17C /*    0 */,    0xE243A8EC, 0xAC424B03 /*    1 */,
    0x0DD5FCD3, 0x72CD5BE3 /*    2 */,    0xF6F97F3A, 0x6D019B93 /*    3 */,
    0xD21F9193, 0xCD9978FF /*    4 */,    0x708029E2, 0x7573A1C9 /*    5 */,
    0x922A83C3, 0xB164326B /*    6 */,    0x04915870, 0x46883EEE /*    7 */,
    0x7103ECE6, 0xEAACE305 /*    8 */,    0x08A3535C, 0xC54169B8 /*    9 */,
    0x8DDEC47C, 0x4CE75491 /*   10 */,    0xDC0DF40C, 0x0AA2F4DF /*   11 */,
    0xA74DBEFA, 0x10B76F18 /*   12 */,    0x5AD1AB6A, 0xC6CCB623 /*   13 */,
    0x572FE2FF, 0x13726121 /*   14 */,    0x199D921E, 0x1A488C6F /*   15 */,
    0xDA0007CA, 0x4BC9F9F4 /*   16 */,    0xE85241C7, 0x26F5E6F6 /*   17 */,
    0xEA5947B6, 0x859079DB /*   18 */,    0xC99E8C92, 0x4F1885C5 /*   19 */,
    0xA96F864B, 0xD78E761E /*   20 */,    0x52B5C17D, 0x8E36428C /*   21 */,
    0x373063C1, 0x69CF6827 /*   22 */,    0x9BB4C56E, 0xB607C93D /*   23 */,
    0x0E76B5EA, 0x7D820E76 /*   24 */,    0xF07FDC42, 0x645C9CC6 /*   25 */,
    0x243342E0, 0xBF38A078 /*   26 */,    0x9D2E7D04, 0x5F6B343C /*   27 */,
    0x600B0EC6, 0xF2C28AEB /*   28 */,    0x7254BCAC, 0x6C0ED85F /*   29 */,
    0xA4DB4FE5, 0x71592281 /*   30 */,    0xCE0FED9F, 0x1967FA69 /*   31 */,
    0xB96545DB, 0xFD5293F8 /*   32 */,    0xF2A7600B, 0xC879E9D7 /*   33 */,
    0x0193194E, 0x86024892 /*   34 */,    0x2D9CC0B3, 0xA4F9533B /*   35 */,
    0x15957613, 0x9053836C /*   36 */,    0xFC357BF1, 0xDB6DCF8A /*   37 */,
    0x7A370F57, 0x18BEEA7A /*   38 */,    0x50B99066, 0x037117CA /*   39 */,
    0x74424A35, 0x6AB30A97 /*   40 */,    0xE325249B, 0xF4E92F02 /*   41 */,
    0x061CCAE1, 0x7739DB07 /*   42 */,    0xECA42A05, 0xD8F3B49C /*   43 */,
    0x51382F73, 0xBD56BE3F /*   44 */,    0x43B0BB28, 0x45FAED58 /*   45 */,
    0x11BF1F83, 0x1C813D5C /*   46 */,    0xD75FA169, 0x8AF0E4B6 /*   47 */,
    0x87AD9999, 0x33EE18A4 /*   48 */,    0xB1C94410, 0x3C26E8EA /*   49 */,
    0xC0A822F9, 0xB510102B /*   50 */,    0x0CE6123B, 0x141EEF31 /*   51 */,
    0x59DDB154, 0xFC65B900 /*   52 */,    0xC5E0E607, 0xE0158640 /*   53 */,
    0x26C3A3CF, 0x884E0798 /*   54 */,    0x23C535FD, 0x930D0D95 /*   55 */,
    0x4E9A2B00, 0x35638D75 /*   56 */,    0x40469DD5, 0x4085FCCF /*   57 */,
    0x8BE23A4C, 0xC4B17AD2 /*   58 */,    0x6A3E6A2E, 0xCAB2F0FC /*   59 */,
    0x6B943FCD, 0x2860971A /*   60 */,    0x12E30446, 0x3DDE6EE2 /*   61 */,
    0xE01765AE, 0x6222F32A /*   62 */,    0x478308FE, 0x5D550BB5 /*   63 */,
    0xA0EDA22A, 0xA9EFA98D /*   64 */,    0x86C40DA7, 0xC351A716 /*   65 */,
    0x9C867C84, 0x1105586D /*   66 */,    0xFDA22853, 0xDCFFEE85 /*   67 */,
    0x2C5EEF76, 0xCCFBD026 /*   68 */,    0x8990D201, 0xBAF294CB /*   69 */,
    0x2AFAD975, 0xE69464F5 /*   70 */,    0xDF133E14, 0x94B013AF /*   71 */,
    0x2823C958, 0x06A7D1A3 /*   72 */,    0x30F61119, 0x6F95FE51 /*   73 */,
    0x462C06C0, 0xD92AB34E /*   74 */,    0x887C71D2, 0xED7BDE33 /*   75 */,
    0x6518393E, 0x79746D6E /*   76 */,    0x5D713329, 0x5BA41938 /*   77 */,
    0x48A97564, 0x7C1BA6B9 /*   78 */,    0x7BFDAC67, 0x31987C19 /*   79 */,
    0x4B053D02, 0xDE6C23C4 /*   80 */,    0xD002D64D, 0x581C49FE /*   81 */,
    0x38261571, 0xDD474D63 /*   82 */,    0xE473D062, 0xAA4546C3 /*   83 */,
    0x9455F860, 0x928FCE34 /*   84 */,    0xCAAB94D9, 0x48161BBA /*   85 */,
    0x770E6F68, 0x63912430 /*   86 */,    0x02C6641C, 0x6EC8A5E6 /*   87 */,
    0x337DDD2B, 0x87282515 /*   88 */,    0x034B701B, 0x2CDA6B42 /*   89 */,
    0x81CB096D, 0xB03D37C1 /*   90 */,    0x66C71C6F, 0xE1084382 /*   91 */,
    0xEB51B255, 0x2B3180C7 /*   92 */,    0x96C08BBC, 0xDF92B82F /*   93 */,
    0xA632F3BA, 0x5C68C8C0 /*   94 */,    0x1C3D0556, 0x5504CC86 /*   95 */,
    0x5FB26B8F, 0xABBFA4E5 /*   96 */,    0xB3BACEB4, 0x41848B0A /*   97 */,
    0xAA445D32, 0xB334A273 /*   98 */,    0xA85AD881, 0xBCA696F0 /*   99 */,
    0xB528D56C, 0x24F6EC65 /*  100 */,    0x90F4524A, 0x0CE1512E /*  101 */,
    0x5506D35A, 0x4E9DD79D /*  102 */,    0xC6CE9779, 0x258905FA /*  103 */,
    0x3E109B33, 0x2019295B /*  104 */,    0x73A054CC, 0xF8A9478B /*  105 */,
    0x34417EB0, 0x2924F2F9 /*  106 */,    0x536D1BC4, 0x3993357D /*  107 */,
    0x1DB6FF8B, 0x38A81AC2 /*  108 */,    0x7D6016BF, 0x47C4FBF1 /*  109 */,
    0x7667E3F5, 0x1E0FAADD /*  110 */,    0x938BEB96, 0x7ABCFF62 /*  111 */,
    0x8FC179C9, 0xA78DAD94 /*  112 */,    0x2911E50D, 0x8F1F98B7 /*  113 */,
    0x27121A91, 0x61E48EAE /*  114 */,    0x31859808, 0x4D62F7AD /*  115 */,
    0xEF5CEAEB, 0xECEBA345 /*  116 */,    0xBC9684CE, 0xF5CEB25E /*  117 */,
    0xB7F76221, 0xF633E20C /*  118 */,    0xAB8293E4, 0xA32CDF06 /*  119 */,
    0xA5EE2CA4, 0x985A202C /*  120 */,    0xCC8A8FB1, 0xCF0B8447 /*  121 */,
    0x979859A3, 0x9F765244 /*  122 */,    0xA1240017, 0xA8D516B1 /*  123 */,
    0xBB5DC726, 0x0BD7BA3E /*  124 */,    0xB86ADB39, 0xE54BCA55 /*  125 */,
    0x6C478063, 0x1D7A3AFD /*  126 */,    0xE7669EDD, 0x519EC608 /*  127 */,
    0xD149AA23, 0x0E5715A2 /*  128 */,    0x848FF194, 0x177D4571 /*  129 */,
    0x41014C22, 0xEEB55F32 /*  130 */,    0x3A6E2EC2, 0x0F5E5CA1 /*  131 */,
    0x75F5C361, 0x8029927B /*  132 */,    0xC3D6E436, 0xAD139FAB /*  133 */,
    0x4CCF402F, 0x0D5DF1A9 /*  134 */,    0xBEA5DFC8, 0x3E8BD948 /*  135 */,
    0xBD3FF77E, 0xA5A0D357 /*  136 */,    0x1F74F645, 0xA2D12E25 /*  137 */,
    0x5E81A082, 0x66FD9E52 /*  138 */,    0x7F687A49, 0x2E0C90CE /*  139 */,
    0xBA973BC5, 0xC2E8BCBE /*  140 */,    0xE509745F, 0x000001BC /*  141 */,
    0xE6DAB3D6, 0x423777BB /*  142 */,    0xAEF06EB5, 0xD1661C7E /*  143 */,
    0x4DAACFD8, 0xA1781F35 /*  144 */,    0x2B16AFFC, 0x2D11284A /*  145 */,
    0xFA891D1F, 0xF1FC4F67 /*  146 */,    0xCB920ADA, 0x73ECC25D /*  147 */,
    0xC2A12651, 0xAE610C22 /*  148 */,    0xD356B78A, 0x96E0A810 /*  149 */,
    0x2FE7870F, 0x5A9A381F /*  150 */,    0xE94E5530, 0xD5AD62ED /*  151 */,
    0x368D1427, 0xD225E5E8 /*  152 */,    0xC7AF4631, 0x65977B70 /*  153 */,
    0xDE39D74F, 0x99F889B2 /*  154 */,    0x54E1D143, 0x233F30BF /*  155 */,
    0xD9A63C97, 0x9A9675D3 /*  156 */,    0xF334F9A8, 0x5470554F /*  157 */,
    0x4A4F5688, 0x166ACB74 /*  158 */,    0xB2E4AEAD, 0x70C74CAA /*  159 */,
    0x6F294D12, 0xF0D09164 /*  160 */,    0x684031D1, 0x57B82A89 /*  161 */,
    0x61BE0B6B, 0xEFD95A5A /*  162 */,    0x69F2F29A, 0x2FBD12E9 /*  163 */,
    0xFEFF9FE8, 0x9BD37013 /*  164 */,    0xD6085A06, 0x3F9B0404 /*  165 */,
    0x166CFE15, 0x4940C1F3 /*  166 */,    0xCDF3DEFB, 0x09542C4D /*  167 */,
    0x85CD5CE3, 0xB4C52183 /*  168 */,    0x4462A641, 0xC935B7DC /*  169 */,
    0x8ED3B63F, 0x3417F8A6 /*  170 */,    0x5B215B40, 0xB8095929 /*  171 */,
    0x3B8C8572, 0xF99CDAEF /*  172 */,    0xF8FCB95D, 0x018C0614 /*  173 */,
    0x1A3ACDF3, 0x1B14ACCD /*  174 */,    0x00BB732D, 0x84D471F2 /*  175 */,
    0x95E8DA16, 0xC1A3110E /*  176 */,    0xBF1A82B8, 0x430A7220 /*  177 */,
    0x39DF210E, 0xB77E090D /*  178 */,    0x3CD05E9D, 0x5EF4BD9F /*  179 */,
    0x7E57A444, 0x9D4FF6DA /*  180 */,    0x83D4A5F8, 0xDA1D60E1 /*  181 */,
    0x17998E47, 0xB287C384 /*  182 */,    0x1BB31886, 0xFE3EDC12 /*  183 */,
    0x980CCBEF, 0xC7FE3CCC /*  184 */,    0x189BFD03, 0xE46FB590 /*  185 */,
    0x9A4C57DC, 0x3732FD46 /*  186 */,    0x7CF1AD65, 0x7EF700A0 /*  187 */,
    0xA31D8859, 0x59C64468 /*  188 */,    0xD45B61F6, 0x762FB0B4 /*  189 */,
    0x99047718, 0x155BAED0 /*  190 */,    0x3D50BAA6, 0x68755E4C /*  191 */,
    0x22D8B4DF, 0xE9214E7F /*  192 */,    0x2EAC95F4, 0x2ADDBF53 /*  193 */,
    0xB4BD0109, 0x32AE3909 /*  194 */,    0xB08E3450, 0x834DF537 /*  195 */,
    0x4220728D, 0xFA209DA8 /*  196 */,    0x9EFE23F7, 0x9E691D9B /*  197 */,
    0xC4AE8D7F, 0x0446D288 /*  198 */,    0xE169785B, 0x7B4CC524 /*  199 */,
    0x35CA1385, 0x21D87F01 /*  200 */,    0x137B8AA5, 0xCEBB400F /*  201 */,
    0x580796BE, 0x272E2B66 /*  202 */,    0x25C2B0DE, 0x36122641 /*  203 */,
    0xAD1EFBB2, 0x057702BD /*  204 */,    0xACF84BE9, 0xD4BABB8E /*  205 */,
    0x641BC67B, 0x91583139 /*  206 */,    0x8036E024, 0x8BDC2DE0 /*  207 */,
    0xF49F68ED, 0x603C8156 /*  208 */,    0xDBEF5111, 0xF7D236F7 /*  209 */,
    0x8AD21E80, 0x9727C459 /*  210 */,    0x670A5FD7, 0xA08A0896 /*  211 */,
    0x09EBA9CB, 0xCB4A8F43 /*  212 */,    0x0F7036A1, 0x81AF564B /*  213 */,
    0x78199ABD, 0xC0B99AA7 /*  214 */,    0x3FC8E952, 0x959F1EC8 /*  215 */,
    0x794A81B9, 0x8C505077 /*  216 */,    0x056338F0, 0x3ACAAF8F /*  217 */,
    0x627A6778, 0x07B43F50 /*  218 */,    0xF5ECCC77, 0x4A44AB49 /*  219 */,
    0xB679EE98, 0x3BC3D6E4 /*  220 */,    0xCF14108C, 0x9CC0D4D1 /*  221 */,
    0x206BC8A0, 0x4406C00B /*  222 */,    0xC8D72D89, 0x82A18854 /*  223 */,
    0x5C3C432C, 0x67E366B3 /*  224 */,    0x102B37F2, 0xB923DD61 /*  225 */,
    0xD884271D, 0x56AB2779 /*  226 */,    0xFF1525AF, 0xBE83E1B0 /*  227 */,
    0x217E49A9, 0xFB7C65D4 /*  228 */,    0x6D48E7D4, 0x6BDBE0E7 /*  229 */,
    0x45D9179E, 0x08DF8287 /*  230 */,    0xDD53BD34, 0x22EA6A9A /*  231 */,
    0x5622200A, 0xE36E141C /*  232 */,    0x8CB750EE, 0x7F805D1B /*  233 */,
    0x9F58E837, 0xAFE5C7A5 /*  234 */,    0x4FB1C23C, 0xE27F996A /*  235 */,
    0x0775F0D0, 0xD3867DFB /*  236 */,    0x6E88891A, 0xD0E673DE /*  237 */,
    0xAFB86C25, 0x123AEB9E /*  238 */,    0xC145B895, 0x30F1D5D5 /*  239 */,
    0xEE7269E7, 0xBB434A2D /*  240 */,    0xF931FA38, 0x78CB67EC /*  241 */,
    0x323BBF9C, 0xF33B0372 /*  242 */,    0xFB279C74, 0x52D66336 /*  243 */,
    0x0AFB4EAA, 0x505F33AC /*  244 */,    0xA2CCE187, 0xE8A5CD99 /*  245 */,
    0x1E2D30BB, 0x53497480 /*  246 */,    0xD5876D90, 0x8D2D5711 /*  247 */,
    0x91BC038E, 0x1F1A4128 /*  248 */,    0x82E56648, 0xD6E2E71D /*  249 */,
    0x497732B7, 0x74036C3A /*  250 */,    0x6361F5AB, 0x89B67ED9 /*  251 */,
    0xF1EA02A2, 0xFFED95D8 /*  252 */,    0x1464D43D, 0xE72B3BD6 /*  253 */,
    0x0BDC4820, 0xA6300F17 /*  254 */,    0xED78A77A, 0xEBC18760 /*  255 */,
    0x05A12138, 0xE6A6BE5A /*  256 */,    0xB4F87C98, 0xB5A122A5 /*  257 */,
    0x140B6990, 0x563C6089 /*  258 */,    0x391F5DD5, 0x4C46CB2E /*  259 */,
    0xC9B79434, 0xD932ADDB /*  260 */,    0x2015AFF5, 0x08EA70E4 /*  261 */,
    0x3E478CF1, 0xD765A667 /*  262 */,    0xAB278D99, 0xC4FB757E /*  263 */,
    0x2D6E0692, 0xDF11C686 /*  264 */,    0x0D7F3B16, 0xDDEB84F1 /*  265 */,
    0xA665EA04, 0x6F2EF604 /*  266 */,    0xF0E0DFB3, 0x4A8E0F0F /*  267 */,
    0x3DBCBA51, 0xA5EDEEF8 /*  268 */,    0x0EA4371E, 0xFC4F0A2A /*  269 */,
    0x5CB38429, 0xE83E1DA8 /*  270 */,    0xBA1B1CE2, 0xDC8FF882 /*  271 */,
    0x8353E80D, 0xCD45505E /*  272 */,    0xD4DB0717, 0x18D19A00 /*  273 */,
    0xA5F38101, 0x34A0CFED /*  274 */,    0x8887CAF2, 0x0BE77E51 /*  275 */,
    0xB3C45136, 0x1E341438 /*  276 */,    0x9089CCF9, 0xE05797F4 /*  277 */,
    0xF2591D14, 0xFFD23F9D /*  278 */,    0x8595C5CD, 0x543DDA22 /*  279 */,
    0x99052A33, 0x661F81FD /*  280 */,    0xDB0F7B76, 0x8736E641 /*  281 */,
    0x418E5307, 0x15227725 /*  282 */,    0x162EB2FA, 0xE25F7F46 /*  283 */,
    0x6C13D9FE, 0x48A8B212 /*  284 */,    0x92E76EEA, 0xAFDC5417 /*  285 */,
    0xC6D1898F, 0x03D912BF /*  286 */,    0x1B83F51B, 0x31B1AAFA /*  287 */,
    0xE42AB7D9, 0xF1AC2796 /*  288 */,    0xFCD2EBAC, 0x40A3A7D7 /*  289 */,
    0x0AFBBCC5, 0x1056136D /*  290 */,    0x9A6D0C85, 0x7889E1DD /*  291 */,
    0x2A7974AA, 0xD3352578 /*  292 */,    0x078AC09B, 0xA7E25D09 /*  293 */,
    0xEAC6EDD0, 0xBD4138B3 /*  294 */,    0x71EB9E70, 0x920ABFBE /*  295 */,
    0x4FC2625C, 0xA2A5D0F5 /*  296 */,    0x0B1290A3, 0xC054E36B /*  297 */,
    0x62FE932B, 0xF6DD59FF /*  298 */,    0x11A8AC7D, 0x35373545 /*  299 */,
    0x72FADCD4, 0xCA845E91 /*  300 */,    0x329D20DC, 0x84F82B60 /*  301 */,
    0xCD672F18, 0x79C62CE1 /*  302 */,    0xD124642C, 0x8B09A2AD /*  303 */,
    0x19D9E726, 0xD0C1E96A /*  304 */,    0x4BA9500C, 0x5A786A9B /*  305 */,
    0x634C43F3, 0x0E020336 /*  306 */,    0xEB66D822, 0xC17B474A /*  307 */,
    0xEC9BAAC2, 0x6A731AE3 /*  308 */,    0xE0840258, 0x8226667A /*  309 */,
    0x91CAECA5, 0x67D45676 /*  310 */,    0x4875ADB5, 0x1D94155C /*  311 */,
    0x5B813FDF, 0x6D00FD98 /*  312 */,    0xB774CD06, 0x51286EFC /*  313 */,
    0x1FA744AF, 0x5E883447 /*  314 */,    0xE761AE2E, 0xF72CA0AE /*  315 */,
    0xAEE8E09A, 0xBE40E4CD /*  316 */,    0x5118F665, 0xE9970BBB /*  317 */,
    0x33DF1964, 0x726E4BEB /*  318 */,    0x29199762, 0x703B0007 /*  319 */,
    0xF5EF30A7, 0x4631D816 /*  320 */,    0x1504A6BE, 0xB880B5B5 /*  321 */,
    0x7ED84B6C, 0x641793C3 /*  322 */,    0xF6E97D96, 0x7B21ED77 /*  323 */,
    0x2EF96B73, 0x77630631 /*  324 */,    0xE86FF3F4, 0xAE528948 /*  325 */,
    0x86A3F8F8, 0x53DBD7F2 /*  326 */,    0x4CFC1063, 0x16CADCE7 /*  327 */,
    0xFA52C6DD, 0x005C19BD /*  328 */,    0x64D46AD3, 0x68868F5D /*  329 */,
    0xCF1E186A, 0x3A9D512C /*  330 */,    0x385660AE, 0x367E62C2 /*  331 */,
    0x77DCB1D7, 0xE359E7EA /*  332 */,    0x749ABE6E, 0x526C0773 /*  333 */,
    0xD09F734B, 0x735AE5F9 /*  334 */,    0x8A558BA8, 0x493FC7CC /*  335 */,
    0x3041AB45, 0xB0B9C153 /*  336 */,    0x470A59BD, 0x321958BA /*  337 */,
    0x5F46C393, 0x852DB00B /*  338 */,    0xD336B0E5, 0x91209B2B /*  339 */,
    0x659EF19F, 0x6E604F7D /*  340 */,    0x782CCB24, 0xB99A8AE2 /*  341 */,
    0xC814C4C7, 0xCCF52AB6 /*  342 */,    0xBE11727B, 0x4727D9AF /*  343 */,
    0x0121B34D, 0x7E950D0C /*  344 */,    0x70AD471F, 0x756F4356 /*  345 */,
    0x615A6849, 0xF5ADD442 /*  346 */,    0x80B9957A, 0x4E87E099 /*  347 */,
    0x50AEE355, 0x2ACFA1DF /*  348 */,    0xFD2FD556, 0xD898263A /*  349 */,
    0xD80C8FD6, 0xC8F4924D /*  350 */,    0x754A173A, 0xCF99CA3D /*  351 */,
    0xAF91BF3C, 0xFE477BAC /*  352 */,    0xD690C12D, 0xED5371F6 /*  353 */,
    0x5E687094, 0x831A5C28 /*  354 */,    0x3708A0A4, 0xC5D3C90A /*  355 */,
    0x17D06580, 0x0F7F9037 /*  356 */,    0xB8FDF27F, 0x19F9BB13 /*  357 */,
    0x4D502843, 0xB1BD6F1B /*  358 */,    0x8FFF4012, 0x1C761BA3 /*  359 */,
    0xE2E21F3B, 0x0D1530C4 /*  360 */,    0xA7372C8A, 0x8943CE69 /*  361 */,
    0xFEB5CE66, 0xE5184E11 /*  362 */,    0xBD736621, 0x618BDB80 /*  363 */,
    0x8B574D0B, 0x7D29BAD6 /*  364 */,    0x25E6FE5B, 0x81BB613E /*  365 */,
    0xBC07913F, 0x071C9C10 /*  366 */,    0x09AC2D97, 0xC7BEEB79 /*  367 */,
    0x3BC5D757, 0xC3E58D35 /*  368 */,    0xF38F61E8, 0xEB017892 /*  369 */,
    0x9B1CC21A, 0xD4EFFB9C /*  370 */,    0xF494F7AB, 0x99727D26 /*  371 */,
    0x956B3E03, 0xA3E063A2 /*  372 */,    0x4AA09C30, 0x9D4A8B9A /*  373 */,
    0x00090FB4, 0x3F6AB7D5 /*  374 */,    0x57268AC0, 0x9CC0F2A0 /*  375 */,
    0xEDBF42D1, 0x3DEE9D2D /*  376 */,    0x7960A972, 0x330F49C8 /*  377 */,
    0x87421B41, 0xC6B27202 /*  378 */,    0x7C00369C, 0x0AC59EC0 /*  379 */,
    0xCB353425, 0xEF4EAC49 /*  380 */,    0xEF0129D8, 0xF450244E /*  381 */,
    0xCAF4DEB6, 0x8ACC46E5 /*  382 */,    0x989263F7, 0x2FFEAB63 /*  383 */,
    0x5D7A4578, 0x8F7CB9FE /*  384 */,    0x4E634635, 0x5BD8F764 /*  385 */,
    0xBF2DC900, 0x427A7315 /*  386 */,    0x2125261C, 0x17D0C4AA /*  387 */,
    0x93518E50, 0x3992486C /*  388 */,    0xA2D7D4C3, 0xB4CBFEE0 /*  389 */,
    0x2C5DDD8D, 0x7C75D620 /*  390 */,    0xE35B6C61, 0xDBC295D8 /*  391 */,
    0x02032B19, 0x60B369D3 /*  392 */,    0xDCE44132, 0xCE42685F /*  393 */,
    0xDDF65610, 0x06F3DDB9 /*  394 */,    0xB5E148F0, 0x8EA4D21D /*  395 */,
    0x2FCD496F, 0x20B0FCE6 /*  396 */,    0x58B0EE31, 0x2C1B9123 /*  397 */,
    0x18F5A308, 0xB28317B8 /*  398 */,    0x9CA6D2CF, 0xA89C1E18 /*  399 */,
    0x6AAADBC8, 0x0C6B1857 /*  400 */,    0x1299FAE3, 0xB65DEAA9 /*  401 */,
    0x7F1027E7, 0xFB2B794B /*  402 */,    0x443B5BEB, 0x04E4317F /*  403 */,
    0x5939D0A6, 0x4B852D32 /*  404 */,    0xFB207FFC, 0xD5AE6BEE /*  405 */,
    0x81C7D374, 0x309682B2 /*  406 */,    0x94C3B475, 0xBAE309A1 /*  407 */,
    0x13B49F05, 0x8CC3F97B /*  408 */,    0xF8293967, 0x98A9422F /*  409 */,
    0x1076FF7C, 0x244B16B0 /*  410 */,    0x663D67EE, 0xF8BF571C /*  411 */,
    0xEEE30DA1, 0x1F0D6758 /*  412 */,    0x7ADEB9B7, 0xC9B611D9 /*  413 */,
    0x7B6C57A2, 0xB7AFD588 /*  414 */,    0x6B984FE1, 0x6290AE84 /*  415 */,
    0xACC1A5FD, 0x94DF4CDE /*  416 */,    0xC5483AFF, 0x058A5BD1 /*  417 */,
    0x42BA3C37, 0x63166CC1 /*  418 */,    0xB2F76F40, 0x8DB8526E /*  419 */,
    0x6F0D6D4E, 0xE1088003 /*  420 */,    0x971D311D, 0x9E0523C9 /*  421 */,
    0xCC7CD691, 0x45EC2824 /*  422 */,    0xE62382C9, 0x575B8359 /*  423 */,
    0xC4889995, 0xFA9E400D /*  424 */,    0x45721568, 0xD1823ECB /*  425 */,
    0x8206082F, 0xDAFD983B /*  426 */,    0x2386A8CB, 0xAA7D2908 /*  427 */,
    0x03B87588, 0x269FCD44 /*  428 */,    0x28BDD1E0, 0x1B91F5F7 /*  429 */,
    0x040201F6, 0xE4669F39 /*  430 */,    0x8CF04ADE, 0x7A1D7C21 /*  431 */,
    0xD79CE5CE, 0x65623C29 /*  432 */,    0x96C00BB1, 0x23684490 /*  433 */,
    0x9DA503BA, 0xAB9BF187 /*  434 */,    0xA458058E, 0xBC23ECB1 /*  435 */,
    0xBB401ECC, 0x9A58DF01 /*  436 */,    0xA85F143D, 0xA070E868 /*  437 */,
    0x7DF2239E, 0x4FF18830 /*  438 */,    0x1A641183, 0x14D565B4 /*  439 */,
    0x52701602, 0xEE133374 /*  440 */,    0x3F285E09, 0x950E3DCF /*  441 */,
    0xB9C80953, 0x59930254 /*  442 */,    0x8930DA6D, 0x3BF29940 /*  443 */,
    0x53691387, 0xA955943F /*  444 */,    0xA9CB8784, 0xA15EDECA /*  445 */,
    0x352BE9A0, 0x29142127 /*  446 */,    0xFF4E7AFB, 0x76F0371F /*  447 */,
    0x274F2228, 0x0239F450 /*  448 */,    0x1D5E868B, 0xBB073AF0 /*  449 */,
    0xC10E96C1, 0xBFC80571 /*  450 */,    0x68222E23, 0xD2670885 /*  451 */,
    0x8E80B5B0, 0x9671A3D4 /*  452 */,    0xE193BB81, 0x55B5D38A /*  453 */,
    0xA18B04B8, 0x693AE2D0 /*  454 */,    0xADD5335F, 0x5C48B4EC /*  455 */,
    0x4916A1CA, 0xFD743B19 /*  456 */,    0x34BE98C4, 0x25770181 /*  457 */,
    0x3C54A4AD, 0xE77987E8 /*  458 */,    0xDA33E1B9, 0x28E11014 /*  459 */,
    0x226AA213, 0x270CC59E /*  460 */,    0x6D1A5F60, 0x71495F75 /*  461 */,
    0x60AFEF77, 0x9BE853FB /*  462 */,    0xF7443DBF, 0xADC786A7 /*  463 */,
    0x73B29A82, 0x09044561 /*  464 */,    0xC232BD5E, 0x58BC7A66 /*  465 */,
    0x673AC8B2, 0xF306558C /*  466 */,    0xB6C9772A, 0x41F639C6 /*  467 */,
    0x9FDA35DA, 0x216DEFE9 /*  468 */,    0x1C7BE615, 0x11640CC7 /*  469 */,
    0x565C5527, 0x93C43694 /*  470 */,    0x46777839, 0xEA038E62 /*  471 */,
    0x5A3E2469, 0xF9ABF3CE /*  472 */,    0x0FD312D2, 0x741E768D /*  473 */,
    0xCED652C6, 0x0144B883 /*  474 */,    0xA33F8552, 0xC20B5A5B /*  475 */,
    0xC3435A9D, 0x1AE69633 /*  476 */,    0x088CFDEC, 0x97A28CA4 /*  477 */,
    0x1E96F420, 0x8824A43C /*  478 */,    0x6EEEA746, 0x37612FA6 /*  479 */,
    0xF9CF0E5A, 0x6B4CB165 /*  480 */,    0xA0ABFB4A, 0x43AA1C06 /*  481 */,
    0xF162796B, 0x7F4DC26F /*  482 */,    0x54ED9B0F, 0x6CBACC8E /*  483 */,
    0xD2BB253E, 0xA6B7FFEF /*  484 */,    0xB0A29D4F, 0x2E25BC95 /*  485 */,
    0xDEF1388C, 0x86D6A58B /*  486 */,    0x76B6F054, 0xDED74AC5 /*  487 */,
    0x2B45805D, 0x8030BDBC /*  488 */,    0xE94D9289, 0x3C81AF70 /*  489 */,
    0x9E3100DB, 0x3EFF6DDA /*  490 */,    0xDFCC8847, 0xB38DC39F /*  491 */,
    0x8D17B87E, 0x12388552 /*  492 */,    0x40B1B642, 0xF2DA0ED2 /*  493 */,
    0xD54BF9A9, 0x44CEFADC /*  494 */,    0x433C7EE6, 0x1312200E /*  495 */,
    0x3A78C748, 0x9FFCC84F /*  496 */,    0x248576BB, 0xF0CD1F72 /*  497 */,
    0x3638CFE4, 0xEC697405 /*  498 */,    0x0CEC4E4C, 0x2BA7B67C /*  499 */,
    0xE5CE32ED, 0xAC2F4DF3 /*  500 */,    0x26EA4C11, 0xCB33D143 /*  501 */,
    0xC77E58BC, 0xA4E9044C /*  502 */,    0xD934FCEF, 0x5F513293 /*  503 */,
    0x06E55444, 0x5DC96455 /*  504 */,    0x317DE40A, 0x50DE418F /*  505 */,
    0x69DDE259, 0x388CB31A /*  506 */,    0x55820A86, 0x2DB4A834 /*  507 */,
    0x84711AE9, 0x9010A91E /*  508 */,    0xB1498371, 0x4DF7F0B7 /*  509 */,
    0xC0977179, 0xD62A2EAB /*  510 */,    0xAA8D5C0E, 0x22FAC097 /*  511 */,
    0xF1DAF39B, 0xF49FCC2F /*  512 */,    0x6FF29281, 0x487FD5C6 /*  513 */,
    0xFCDCA83F, 0xE8A30667 /*  514 */,    0xD2FCCE63, 0x2C9B4BE3 /*  515 */,
    0x93FBBBC2, 0xDA3FF74B /*  516 */,    0xFE70BA66, 0x2FA165D2 /*  517 */,
    0x970E93D4, 0xA103E279 /*  518 */,    0xB0E45E71, 0xBECDEC77 /*  519 */,
    0x3985E497, 0xCFB41E72 /*  520 */,    0x5EF75017, 0xB70AAA02 /*  521 */,
    0x3840B8E0, 0xD42309F0 /*  522 */,    0x35898579, 0x8EFC1AD0 /*  523 */,
    0xE2B2ABC5, 0x96C6920B /*  524 */,    0x375A9172, 0x66AF4163 /*  525 */,
    0xCA7127FB, 0x2174ABDC /*  526 */,    0x4A72FF41, 0xB33CCEA6 /*  527 */,
    0x083066A5, 0xF04A4933 /*  528 */,    0xD7289AF5, 0x8D970ACD /*  529 */,
    0x31C8C25E, 0x8F96E8E0 /*  530 */,    0x76875D47, 0xF3FEC022 /*  531 */,
    0x056190DD, 0xEC7BF310 /*  532 */,    0xBB0F1491, 0xF5ADB0AE /*  533 */,
    0x0FD58892, 0x9B50F885 /*  534 */,    0x58B74DE8, 0x49754883 /*  535 */,
    0x91531C61, 0xA3354FF6 /*  536 */,    0x81D2C6EE, 0x0702BBE4 /*  537 */,
    0x7DEDED98, 0x89FB2405 /*  538 */,    0x8596E902, 0xAC307513 /*  539 */,
    0x172772ED, 0x1D2D3580 /*  540 */,    0x8E6BC30D, 0xEB738FC2 /*  541 */,
    0x63044326, 0x5854EF8F /*  542 */,    0x5ADD3BBE, 0x9E5C5232 /*  543 */,
    0x325C4623, 0x90AA53CF /*  544 */,    0x349DD067, 0xC1D24D51 /*  545 */,
    0xA69EA624, 0x2051CFEE /*  546 */,    0x862E7E4F, 0x13220F0A /*  547 */,
    0x04E04864, 0xCE393994 /*  548 */,    0x7086FCB7, 0xD9C42CA4 /*  549 */,
    0x8A03E7CC, 0x685AD223 /*  550 */,    0xAB2FF1DB, 0x066484B2 /*  551 */,
    0xEFBF79EC, 0xFE9D5D70 /*  552 */,    0x9C481854, 0x5B13B9DD /*  553 */,
    0xED1509AD, 0x15F0D475 /*  554 */,    0x0EC79851, 0x0BEBCD06 /*  555 */,
    0x183AB7F8, 0xD58C6791 /*  556 */,    0x52F3EEE4, 0xD1187C50 /*  557 */,
    0xE54E82FF, 0xC95D1192 /*  558 */,    0xB9AC6CA2, 0x86EEA14C /*  559 */,
    0x53677D5D, 0x3485BEB1 /*  560 */,    0x1F8C492A, 0xDD191D78 /*  561 */,
    0xA784EBF9, 0xF60866BA /*  562 */,    0xA2D08C74, 0x518F643B /*  563 */,
    0xE1087C22, 0x8852E956 /*  564 */,    0xC410AE8D, 0xA768CB8D /*  565 */,
    0xBFEC8E1A, 0x38047726 /*  566 */,    0xCD3B45AA, 0xA67738B4 /*  567 */,
    0xEC0DDE19, 0xAD16691C /*  568 */,    0x80462E07, 0xC6D43193 /*  569 */,
    0x0BA61938, 0xC5A5876D /*  570 */,    0xA58FD840, 0x16B9FA1F /*  571 */,
    0x3CA74F18, 0x188AB117 /*  572 */,    0xC99C021F, 0xABDA2F98 /*  573 */,
    0x134AE816, 0x3E0580AB /*  574 */,    0x73645ABB, 0x5F3B05B7 /*  575 */,
    0x5575F2F6, 0x2501A2BE /*  576 */,    0x4E7E8BA9, 0x1B2F7400 /*  577 */,
    0x71E8D953, 0x1CD75803 /*  578 */,    0x62764E30, 0x7F6ED895 /*  579 */,
    0x596F003D, 0xB15926FF /*  580 */,    0xA8C5D6B9, 0x9F65293D /*  581 */,
    0xD690F84C, 0x6ECEF04D /*  582 */,    0xFF33AF88, 0x4782275F /*  583 */,
    0x3F820801, 0xE4143308 /*  584 */,    0x9A1AF9B5, 0xFD0DFE40 /*  585 */,
    0x2CDB396B, 0x4325A334 /*  586 */,    0xB301B252, 0x8AE77E62 /*  587 */,
    0x6655615A, 0xC36F9E9F /*  588 */,    0x92D32C09, 0x85455A2D /*  589 */,
    0x49477485, 0xF2C7DEA9 /*  590 */,    0x33A39EBA, 0x63CFB4C1 /*  591 */,
    0x6EBC5462, 0x83B040CC /*  592 */,    0xFDB326B0, 0x3B9454C8 /*  593 */,
    0x87FFD78C, 0x56F56A9E /*  594 */,    0x99F42BC6, 0x2DC2940D /*  595 */,
    0x6B096E2D, 0x98F7DF09 /*  596 */,    0x3AD852BF, 0x19A6E01E /*  597 */,
    0xDBD4B40B, 0x42A99CCB /*  598 */,    0x45E9C559, 0xA59998AF /*  599 */,
    0x07D93186, 0x366295E8 /*  600 */,    0xFAA1F773, 0x6B48181B /*  601 */,
    0x157A0A1D, 0x1FEC57E2 /*  602 */,    0xF6201AD5, 0x4667446A /*  603 */,
    0xCFB0F075, 0xE615EBCA /*  604 */,    0x68290778, 0xB8F31F4F /*  605 */,
    0xCE22D11E, 0x22713ED6 /*  606 */,    0x2EC3C93B, 0x3057C1A7 /*  607 */,
    0x7C3F1F2F, 0xCB46ACC3 /*  608 */,    0x02AAF50E, 0xDBB893FD /*  609 */,
    0x600B9FCF, 0x331FD92E /*  610 */,    0x48EA3AD6, 0xA498F961 /*  611 */,
    0x8B6A83EA, 0xA8D8426E /*  612 */,    0xB7735CDC, 0xA089B274 /*  613 */,
    0x1E524A11, 0x87F6B373 /*  614 */,    0xCBC96749, 0x118808E5 /*  615 */,
    0xB19BD394, 0x9906E4C7 /*  616 */,    0x9B24A20C, 0xAFED7F7E /*  617 */,
    0xEB3644A7, 0x6509EADE /*  618 */,    0xE8EF0EDE, 0x6C1EF1D3 /*  619 */,
    0xE9798FB4, 0xB9C97D43 /*  620 */,    0x740C28A3, 0xA2F2D784 /*  621 */,
    0x6197566F, 0x7B849647 /*  622 */,    0xB65F069D, 0x7A5BE3E6 /*  623 */,
    0x78BE6F10, 0xF96330ED /*  624 */,    0x7A076A15, 0xEEE60DE7 /*  625 */,
    0xA08B9BD0, 0x2B4BEE4A /*  626 */,    0xC7B8894E, 0x6A56A63E /*  627 */,
    0xBA34FEF4, 0x02121359 /*  628 */,    0x283703FC, 0x4CBF99F8 /*  629 */,
    0x0CAF30C8, 0x39807135 /*  630 */,    0xF017687A, 0xD0A77A89 /*  631 */,
    0x9E423569, 0xF1C1A9EB /*  632 */,    0x2DEE8199, 0x8C797628 /*  633 */,
    0xDD1F7ABD, 0x5D1737A5 /*  634 */,    0x09A9FA80, 0x4F53433C /*  635 */,
    0xDF7CA1D9, 0xFA8B0C53 /*  636 */,    0x886CCB77, 0x3FD9DCBC /*  637 */,
    0xA91B4720, 0xC040917C /*  638 */,    0xF9D1DCDF, 0x7DD00142 /*  639 */,
    0x4F387B58, 0x8476FC1D /*  640 */,    0xF3316503, 0x23F8E7C5 /*  641 */,
    0xE7E37339, 0x032A2244 /*  642 */,    0x50F5A74B, 0x5C87A5D7 /*  643 */,
    0x3698992E, 0x082B4CC4 /*  644 */,    0xB858F63C, 0xDF917BEC /*  645 */,
    0x5BF86DDA, 0x3270B8FC /*  646 */,    0x29B5DD76, 0x10AE72BB /*  647 */,
    0x7700362B, 0x576AC94E /*  648 */,    0xC61EFB8F, 0x1AD112DA /*  649 */,
    0xC5FAA427, 0x691BC30E /*  650 */,    0xCC327143, 0xFF246311 /*  651 */,
    0x30E53206, 0x3142368E /*  652 */,    0xE02CA396, 0x71380E31 /*  653 */,
    0x0AAD76F1, 0x958D5C96 /*  654 */,    0xC16DA536, 0xF8D6F430 /*  655 */,
    0x1BE7E1D2, 0xC8FFD13F /*  656 */,    0x004DDBE1, 0x7578AE66 /*  657 */,
    0x067BE646, 0x05833F01 /*  658 */,    0x3BFE586D, 0xBB34B5AD /*  659 */,
    0xA12B97F0, 0x095F34C9 /*  660 */,    0x25D60CA8, 0x247AB645 /*  661 */,
    0x017477D1, 0xDCDBC6F3 /*  662 */,    0xDECAD24D, 0x4A2E14D4 /*  663 */,
    0xBE0A1EEB, 0xBDB5E6D9 /*  664 */,    0x794301AB, 0x2A7E70F7 /*  665 */,
    0x270540FD, 0xDEF42D8A /*  666 */,    0xA34C22C1, 0x01078EC0 /*  667 */,
    0xF4C16387, 0xE5DE511A /*  668 */,    0xBD9A330A, 0x7EBB3A52 /*  669 */,
    0xAA7D6435, 0x77697857 /*  670 */,    0x03AE4C32, 0x004E8316 /*  671 */,
    0xAD78E312, 0xE7A21020 /*  672 */,    0x6AB420F2, 0x9D41A70C /*  673 */,
    0xEA1141E6, 0x28E06C18 /*  674 */,    0x984F6B28, 0xD2B28CBD /*  675 */,
    0x446E9D83, 0x26B75F6C /*  676 */,    0x4D418D7F, 0xBA47568C /*  677 */,
    0xE6183D8E, 0xD80BADBF /*  678 */,    0x5F166044, 0x0E206D7F /*  679 */,
    0x11CBCA3E, 0xE258A439 /*  680 */,    0xB21DC0BC, 0x723A1746 /*  681 */,
    0xF5D7CDD3, 0xC7CAA854 /*  682 */,    0x3D261D9C, 0x7CAC3288 /*  683 */,
    0x23BA942C, 0x7690C264 /*  684 */,    0x478042B8, 0x17E55524 /*  685 */,
    0x56A2389F, 0xE0BE4776 /*  686 */,    0x67AB2DA0, 0x4D289B5E /*  687 */,
    0x8FBBFD31, 0x44862B9C /*  688 */,    0x9D141365, 0xB47CC804 /*  689 */,
    0x2B91C793, 0x822C1B36 /*  690 */,    0xFB13DFD8, 0x4EB14655 /*  691 */,
    0x14E2A97B, 0x1ECBBA07 /*  692 */,    0x5CDE5F14, 0x6143459D /*  693 */,
    0xD5F0AC89, 0x53A8FBF1 /*  694 */,    0x1C5E5B00, 0x97EA04D8 /*  695 */,
    0xD4FDB3F3, 0x622181A8 /*  696 */,    0x572A1208, 0xE9BCD341 /*  697 */,
    0x43CCE58A, 0x14112586 /*  698 */,    0xA4C6E0A4, 0x9144C5FE /*  699 */,
    0x65CF620F, 0x0D33D065 /*  700 */,    0x9F219CA1, 0x54A48D48 /*  701 */,
    0x6D63C821, 0xC43E5EAC /*  702 */,    0x72770DAF, 0xA9728B3A /*  703 */,
    0x20DF87EF, 0xD7934E7B /*  704 */,    0x1A3E86E5, 0xE35503B6 /*  705 */,
    0xC819D504, 0xCAE321FB /*  706 */,    0xAC60BFA6, 0x129A50B3 /*  707 */,
    0x7E9FB6C3, 0xCD5E68EA /*  708 */,    0x9483B1C7, 0xB01C9019 /*  709 */,
    0xC295376C, 0x3DE93CD5 /*  710 */,    0x2AB9AD13, 0xAED52EDF /*  711 */,
    0xC0A07884, 0x2E60F512 /*  712 */,    0xE36210C9, 0xBC3D86A3 /*  713 */,
    0x163951CE, 0x35269D9B /*  714 */,    0xD0CDB5FA, 0x0C7D6E2A /*  715 */,
    0xD87F5733, 0x59E86297 /*  716 */,    0x898DB0E7, 0x298EF221 /*  717 */,
    0xD1A5AA7E, 0x55000029 /*  718 */,    0xB5061B45, 0x8BC08AE1 /*  719 */,
    0x6C92703A, 0xC2C31C2B /*  720 */,    0xAF25EF42, 0x94CC596B /*  721 */,
    0x22540456, 0x0A1D73DB /*  722 */,    0xD9C4179A, 0x04B6A0F9 /*  723 */,
    0xAE3D3C60, 0xEFFDAFA2 /*  724 */,    0xB49496C4, 0xF7C8075B /*  725 */,
    0x1D1CD4E3, 0x9CC5C714 /*  726 */,    0x218E5534, 0x78BD1638 /*  727 */,
    0xF850246A, 0xB2F11568 /*  728 */,    0x9502BC29, 0xEDFABCFA /*  729 */,
    0xDA23051B, 0x796CE5F2 /*  730 */,    0xDC93537C, 0xAAE128B0 /*  731 */,
    0xEE4B29AE, 0x3A493DA0 /*  732 */,    0x416895D7, 0xB5DF6B2C /*  733 */,
    0x122D7F37, 0xFCABBD25 /*  734 */,    0x105DC4B1, 0x70810B58 /*  735 */,
    0xF7882A90, 0xE10FDD37 /*  736 */,    0x518A3F5C, 0x524DCAB5 /*  737 */,
    0x8451255B, 0x3C9E8587 /*  738 */,    0x19BD34E2, 0x40298281 /*  739 */,
    0x5D3CECCB, 0x74A05B6F /*  740 */,    0x42E13ECA, 0xB6100215 /*  741 */,
    0x2F59E2AC, 0x0FF979D1 /*  742 */,    0xE4F9CC50, 0x6037DA27 /*  743 */,
    0x0DF1847D, 0x5E92975A /*  744 */,    0xD3E623FE, 0xD66DE190 /*  745 */,
    0x7B568048, 0x5032D6B8 /*  746 */,    0x8235216E, 0x9A36B7CE /*  747 */,
    0x24F64B4A, 0x80272A7A /*  748 */,    0x8C6916F7, 0x93EFED8B /*  749 */,
    0x4CCE1555, 0x37DDBFF4 /*  750 */,    0x4B99BD25, 0x4B95DB5D /*  751 */,
    0x69812FC0, 0x92D3FDA1 /*  752 */,    0x90660BB6, 0xFB1A4A9A /*  753 */,
    0x46A4B9B2, 0x730C1969 /*  754 */,    0x7F49DA68, 0x81E289AA /*  755 */,
    0x83B1A05F, 0x64669A0F /*  756 */,    0x9644F48B, 0x27B3FF7D /*  757 */,
    0x8DB675B3, 0xCC6B615C /*  758 */,    0xBCEBBE95, 0x674F20B9 /*  759 */,
    0x75655982, 0x6F312382 /*  760 */,    0x3E45CF05, 0x5AE48871 /*  761 */,
    0x54C21157, 0xBF619F99 /*  762 */,    0x40A8EAE9, 0xEABAC460 /*  763 */,
    0xF2C0C1CD, 0x454C6FE9 /*  764 */,    0x6412691C, 0x419CF649 /*  765 */,
    0x265B0F70, 0xD3DC3BEF /*  766 */,    0xC3578A9E, 0x6D0E60F5 /*  767 */,
    0x26323C55, 0x5B0E6085 /*  768 */,    0xFA1B59F5, 0x1A46C1A9 /*  769 */,
    0x7C4C8FFA, 0xA9E245A1 /*  770 */,    0xDB2955D7, 0x65CA5159 /*  771 */,
    0xCE35AFC2, 0x05DB0A76 /*  772 */,    0xA9113D45, 0x81EAC77E /*  773 */,
    0xB6AC0A0D, 0x528EF88A /*  774 */,    0x597BE3FF, 0xA09EA253 /*  775 */,
    0xAC48CD56, 0x430DDFB3 /*  776 */,    0xF45CE46F, 0xC4B3A67A /*  777 */,
    0xFBE2D05E, 0x4ECECFD8 /*  778 */,    0xB39935F0, 0x3EF56F10 /*  779 */,
    0x9CD619C6, 0x0B22D682 /*  780 */,    0x74DF2069, 0x17FD460A /*  781 */,
    0x8510ED40, 0x6CF8CC8E /*  782 */,    0x3A6ECAA7, 0xD6C824BF /*  783 */,
    0x1A817049, 0x61243D58 /*  784 */,    0xBBC163A2, 0x048BACB6 /*  785 */,
    0x7D44CC32, 0xD9A38AC2 /*  786 */,    0xAAF410AB, 0x7FDDFF5B /*  787 */,
    0xA804824B, 0xAD6D495A /*  788 */,    0x2D8C9F94, 0xE1A6A74F /*  789 */,
    0x35DEE8E3, 0xD4F78512 /*  790 */,    0x6540D893, 0xFD4B7F88 /*  791 */,
    0x2AA4BFDA, 0x247C2004 /*  792 */,    0x17D1327C, 0x096EA1C5 /*  793 */,
    0x361A6685, 0xD56966B4 /*  794 */,    0x1221057D, 0x277DA5C3 /*  795 */,
    0xA43ACFF7, 0x94D59893 /*  796 */,    0xCDC02281, 0x64F0C51C /*  797 */,
    0xFF6189DB, 0x3D33BCC4 /*  798 */,    0x4CE66AF1, 0xE005CB18 /*  799 */,
    0x1DB99BEA, 0xFF5CCD1D /*  800 */,    0xFE42980F, 0xB0B854A7 /*  801 */,
    0x718D4B9F, 0x7BD46A6A /*  802 */,    0x22A5FD8C, 0xD10FA8CC /*  803 */,
    0x2BE4BD31, 0xD3148495 /*  804 */,    0xCB243847, 0xC7FA975F /*  805 */,
    0x5846C407, 0x4886ED1E /*  806 */,    0x1EB70B04, 0x28CDDB79 /*  807 */,
    0xF573417F, 0xC2B00BE2 /*  808 */,    0x2180F877, 0x5C959045 /*  809 */,
    0xF370EB00, 0x7A6BDDFF /*  810 */,    0xD6D9D6A4, 0xCE509E38 /*  811 */,
    0x647FA702, 0xEBEB0F00 /*  812 */,    0x76606F06, 0x1DCC06CF /*  813 */,
    0xA286FF0A, 0xE4D9F28B /*  814 */,    0xC918C262, 0xD85A305D /*  815 */,
    0x32225F54, 0x475B1D87 /*  816 */,    0x68CCB5FE, 0x2D4FB516 /*  817 */,
    0xD72BBA20, 0xA679B9D9 /*  818 */,    0x912D43A5, 0x53841C0D /*  819 */,
    0xBF12A4E8, 0x3B7EAA48 /*  820 */,    0xF22F1DDF, 0x781E0E47 /*  821 */,
    0x0AB50973, 0xEFF20CE6 /*  822 */,    0x9DFFB742, 0x20D261D1 /*  823 */,
    0x062A2E39, 0x16A12B03 /*  824 */,    0x39650495, 0x1960EB22 /*  825 */,
    0xD50EB8B8, 0x251C16FE /*  826 */,    0xF826016E, 0x9AC0C330 /*  827 */,
    0x953E7671, 0xED152665 /*  828 */,    0xA6369570, 0x02D63194 /*  829 */,
    0x94B1C987, 0x5074F083 /*  830 */,    0x90B25CE1, 0x70BA598C /*  831 */,
    0x0B9742F6, 0x794A1581 /*  832 */,    0xFCAF8C6C, 0x0D5925E9 /*  833 */,
    0xD868744E, 0x3067716C /*  834 */,    0xE8D7731B, 0x910AB077 /*  835 */,
    0x5AC42F61, 0x6A61BBDB /*  836 */,    0xF0851567, 0x93513EFB /*  837 */,
    0x9E83E9D5, 0xF494724B /*  838 */,    0x5C09648D, 0xE887E198 /*  839 */,
    0x75370CFD, 0x34B1D3C6 /*  840 */,    0xBC0D255D, 0xDC35E433 /*  841 */,
    0x34131BE0, 0xD0AAB842 /*  842 */,    0xB48B7EAF, 0x08042A50 /*  843 */,
    0x44A3AB35, 0x9997C4EE /*  844 */,    0x201799D0, 0x829A7B49 /*  845 */,
    0xB7C54441, 0x263B8307 /*  846 */,    0xFD6A6CA6, 0x752F95F4 /*  847 */,
    0x2C08C6E5, 0x92721740 /*  848 */,    0xA795D9EE, 0x2A8AB754 /*  849 */,
    0x2F72943D, 0xA442F755 /*  850 */,    0x19781208, 0x2C31334E /*  851 */,
    0xEAEE6291, 0x4FA98D7C /*  852 */,    0x665DB309, 0x55C3862F /*  853 */,
    0x5D53B1F3, 0xBD061017 /*  854 */,    0x40413F27, 0x46FE6CB8 /*  855 */,
    0xDF0CFA59, 0x3FE03792 /*  856 */,    0x2EB85E8F, 0xCFE70037 /*  857 */,
    0xADBCE118, 0xA7BE29E7 /*  858 */,    0xDE8431DD, 0xE544EE5C /*  859 */,
    0x41F1873E, 0x8A781B1B /*  860 */,    0xA0D2F0E7, 0xA5C94C78 /*  861 */,
    0x77B60728, 0x39412E28 /*  862 */,    0xAFC9A62C, 0xA1265EF3 /*  863 */,
    0x6A2506C5, 0xBCC2770C /*  864 */,    0xDCE1CE12, 0x3AB66DD5 /*  865 */,
    0x4A675B37, 0xE65499D0 /*  866 */,    0x81BFD216, 0x7D8F5234 /*  867 */,
    0xEC15F389, 0x0F6F64FC /*  868 */,    0x8B5B13C8, 0x74EFBE61 /*  869 */,
    0x14273E1D, 0xACDC82B7 /*  870 */,    0x03199D17, 0xDD40BFE0 /*  871 */,
    0xE7E061F8, 0x37E99257 /*  872 */,    0x04775AAA, 0xFA526269 /*  873 */,
    0x463D56F9, 0x8BBBF63A /*  874 */,    0x43A26E64, 0xF0013F15 /*  875 */,
    0x879EC898, 0xA8307E9F /*  876 */,    0x150177CC, 0xCC4C27A4 /*  877 */,
    0xCA1D3348, 0x1B432F2C /*  878 */,    0x9F6FA013, 0xDE1D1F8F /*  879 */,
    0x47A7DDD6, 0x606602A0 /*  880 */,    0xCC1CB2C7, 0xD237AB64 /*  881 */,
    0x25FCD1D3, 0x9B938E72 /*  882 */,    0x8E0FF476, 0xEC4E0370 /*  883 */,
    0x3D03C12D, 0xFEB2FBDA /*  884 */,    0xEE43889A, 0xAE0BCED2 /*  885 */,
    0xEBFB4F43, 0x22CB8923 /*  886 */,    0x3CF7396D, 0x69360D01 /*  887 */,
    0xD2D4E022, 0x855E3602 /*  888 */,    0xD01F784C, 0x073805BA /*  889 */,
    0x3852F546, 0x33E17A13 /*  890 */,    0x8AC7B638, 0xDF487405 /*  891 */,
    0x678AA14A, 0xBA92B29C /*  892 */,    0x6CFAADCD, 0x0CE89FC7 /*  893 */,
    0x08339E34, 0x5F9D4E09 /*  894 */,    0x1F5923B9, 0xF1AFE929 /*  895 */,
    0x0F4A265F, 0x6E3480F6 /*  896 */,    0xB29B841C, 0xEEBF3A2A /*  897 */,
    0x8F91B4AD, 0xE21938A8 /*  898 */,    0x45C6D3C3, 0x57DFEFF8 /*  899 */,
    0xF62CAAF2, 0x2F006B0B /*  900 */,    0x6F75EE78, 0x62F479EF /*  901 */,
    0x1C8916A9, 0x11A55AD4 /*  902 */,    0x84FED453, 0xF229D290 /*  903 */,
    0x16B000E6, 0x42F1C27B /*  904 */,    0x9823C074, 0x2B1F7674 /*  905 */,
    0xC2745360, 0x4B76ECA3 /*  906 */,    0xB91691BD, 0x8C98F463 /*  907 */,
    0xF1ADE66A, 0x14BCC93C /*  908 */,    0x6D458397, 0x8885213E /*  909 */,
    0x274D4711, 0x8E177DF0 /*  910 */,    0x503F2951, 0xB49B73B5 /*  911 */,
    0xC3F96B6B, 0x10168168 /*  912 */,    0x63CAB0AE, 0x0E3D963B /*  913 */,
    0x55A1DB14, 0x8DFC4B56 /*  914 */,    0x6E14DE5C, 0xF789F135 /*  915 */,
    0x4E51DAC1, 0x683E68AF /*  916 */,    0x8D4B0FD9, 0xC9A84F9D /*  917 */,
    0x52A0F9D1, 0x3691E03F /*  918 */,    0xE1878E80, 0x5ED86E46 /*  919 */,
    0x99D07150, 0x3C711A0E /*  920 */,    0x0C4E9310, 0x5A0865B2 /*  921 */,
    0xE4F0682E, 0x56FBFC1F /*  922 */,    0x105EDF9B, 0xEA8D5DE3 /*  923 */,
    0x2379187A, 0x71ABFDB1 /*  924 */,    0xBEE77B9C, 0x2EB99DE1 /*  925 */,
    0x33CF4523, 0x21ECC0EA /*  926 */,    0x1805C7A1, 0x59A4D752 /*  927 */,
    0x56AE7C72, 0x3896F5EB /*  928 */,    0xB18F75DC, 0xAA638F3D /*  929 */,
    0xABE9808E, 0x9F39358D /*  930 */,    0xC00B72AC, 0xB7DEFA91 /*  931 */,
    0x62492D92, 0x6B5541FD /*  932 */,    0xF92E4D5B, 0x6DC6DEE8 /*  933 */,
    0xC4BEEA7E, 0x353F57AB /*  934 */,    0xDA5690CE, 0x735769D6 /*  935 */,
    0x42391484, 0x0A234AA6 /*  936 */,    0x28F80D9D, 0xF6F95080 /*  937 */,
    0x7AB3F215, 0xB8E319A2 /*  938 */,    0x51341A4D, 0x31AD9C11 /*  939 */,
    0x7BEF5805, 0x773C22A5 /*  940 */,    0x07968633, 0x45C7561A /*  941 */,
    0x249DBE36, 0xF913DA9E /*  942 */,    0x78A64C68, 0xDA652D9B /*  943 */,
    0x3BC334EF, 0x4C27A97F /*  944 */,    0xE66B17F4, 0x76621220 /*  945 */,
    0x9ACD7D0B, 0x96774389 /*  946 */,    0xE0ED6782, 0xF3EE5BCA /*  947 */,
    0x00C879FC, 0x409F7536 /*  948 */,    0xB5926DB6, 0x06D09A39 /*  949 */,
    0x317AC588, 0x6F83AEB0 /*  950 */,    0x86381F21, 0x01E6CA4A /*  951 */,
    0xD19F3025, 0x66FF3462 /*  952 */,    0xDDFD3BFB, 0x72207C24 /*  953 */,
    0xE2ECE2EB, 0x4AF6B6D3 /*  954 */,    0xC7EA08DE, 0x9C994DBE /*  955 */,
    0xB09A8BC4, 0x49ACE597 /*  956 */,    0xCF0797BA, 0xB38C4766 /*  957 */,
    0xC57C2A75, 0x131B9373 /*  958 */,    0x61931E58, 0xB1822CCE /*  959 */,
    0x09BA1C0C, 0x9D7555B9 /*  960 */,    0x937D11D2, 0x127FAFDD /*  961 */,
    0xC66D92E4, 0x29DA3BAD /*  962 */,    0x54C2ECBC, 0xA2C1D571 /*  963 */,
    0x82F6FE24, 0x58C5134D /*  964 */,    0x5B62274F, 0x1C3AE351 /*  965 */,
    0x01CB8126, 0xE907C82E /*  966 */,    0x13E37FCB, 0xF8ED0919 /*  967 */,
    0xC80046C9, 0x3249D8F9 /*  968 */,    0xE388FB63, 0x80CF9BED /*  969 */,
    0x116CF19E, 0x1881539A /*  970 */,    0x6BD52457, 0x5103F3F7 /*  971 */,
    0xAE47F7A8, 0x15B7E6F5 /*  972 */,    0xD47E9CCF, 0xDBD7C6DE /*  973 */,
    0x0228BB1A, 0x44E55C41 /*  974 */,    0x5EDB4E99, 0xB647D425 /*  975 */,
    0xB8AAFC30, 0x5D11882B /*  976 */,    0x29D3212A, 0xF5098BBB /*  977 */,
    0xE90296B3, 0x8FB5EA14 /*  978 */,    0x57DD025A, 0x677B9421 /*  979 */,
    0xA390ACB5, 0xFB58E7C0 /*  980 */,    0x83BD4A01, 0x89D3674C /*  981 */,
    0x4BF3B93B, 0x9E2DA4DF /*  982 */,    0x8CAB4829, 0xFCC41E32 /*  983 */,
    0xBA582C52, 0x03F38C96 /*  984 */,    0x7FD85DB2, 0xCAD1BDBD /*  985 */,
    0x6082AE83, 0xBBB442C1 /*  986 */,    0xA5DA9AB0, 0xB95FE86B /*  987 */,
    0x3771A93F, 0xB22E0467 /*  988 */,    0x493152D8, 0x845358C9 /*  989 */,
    0x97B4541E, 0xBE2A4886 /*  990 */,    0xD38E6966, 0x95A2DC2D /*  991 */,
    0x923C852B, 0xC02C11AC /*  992 */,    0x0DF2A87B, 0x2388B199 /*  993 */,
    0x1B4F37BE, 0x7C8008FA /*  994 */,    0x4D54E503, 0x1F70D0C8 /*  995 */,
    0x7ECE57D4, 0x5490ADEC /*  996 */,    0xD9063A3A, 0x002B3C27 /*  997 */,
    0x8030A2BF, 0x7EAEA384 /*  998 */,    0xED2003C0, 0xC602326D /*  999 */,
    0x69A94086, 0x83A7287D /* 1000 */,    0x30F57A8A, 0xC57A5FCB /* 1001 */,
    0x79EBE779, 0xB56844E4 /* 1002 */,    0x05DCBCE9, 0xA373B40F /* 1003 */,
    0x88570EE2, 0xD71A786E /* 1004 */,    0xBDE8F6A0, 0x879CBACD /* 1005 */,
    0xC164A32F, 0x976AD1BC /* 1006 */,    0x9666D78B, 0xAB21E25E /* 1007 */,
    0xE5E5C33C, 0x901063AA /* 1008 */,    0x48698D90, 0x9818B344 /* 1009 */,
    0x3E1E8ABB, 0xE36487AE /* 1010 */,    0x893BDCB4, 0xAFBDF931 /* 1011 */,
    0x5FBBD519, 0x6345A0DC /* 1012 */,    0x9B9465CA, 0x8628FE26 /* 1013 */,
    0x3F9C51EC, 0x1E5D0160 /* 1014 */,    0xA15049B7, 0x4DE44006 /* 1015 */,
    0xF776CBB1, 0xBF6C70E5 /* 1016 */,    0xEF552BED, 0x411218F2 /* 1017 */,
    0x705A36A3, 0xCB0C0708 /* 1018 */,    0x4F986044, 0xE74D1475 /* 1019 */,
    0x0EA8280E, 0xCD56D943 /* 1020 */,    0x535F5065, 0xC12591D7 /* 1021 */,
    0x720AEF96, 0xC83223F1 /* 1022 */,    0x7363A51F, 0xC3A0396F /* 1023 */};


#endif