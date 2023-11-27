//! These tests were generated using the following Python script:
//! ```py
//! from random import randrange
//!
//! MIN = 0
//! MAX = 2**256 - 1
//! MOD = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
//! DIGIT_BITS = 64
//!
//! def into_list(n):
//!    a = []
//!    while len(a) != 4:
//!        a.append(n & (2**DIGIT_BITS - 1))
//!        n >>= DIGIT_BITS
//!    return a
//!
//! def addition():
//!    result = []
//!    for _ in range(0, 10):
//!        a = randrange(MIN, MAX)
//!        b = randrange(MIN, MAX)
//!        c = (a + b) % MOD
//!        result.append([into_list(a), into_list(b), into_list(c)])
//!    print("let cases = ", result, ";")
//!
//! def subtraction():
//!    result = []
//!    for _ in range(0, 10):
//!        a = randrange(MIN, MAX)
//!        b = randrange(MIN, MAX)
//!        c = (a - b) % MOD
//!        result.append([into_list(a), into_list(b), into_list(c)])
//!    print("let cases = ", result, ";")
//!
//! def multiplication():
//!    result = []
//!    for _ in range(0, 10):
//!        a = randrange(MIN, MAX)
//!        b = randrange(MIN, MAX)
//!        c = (a * b) % MOD
//!        result.append([into_list(a), into_list(b), into_list(c)])
//!    print("let cases = ", result, ";")
//!
//! def inversion():
//!    result = []
//!    for _ in range(0, 10):
//!        a = randrange(MIN, MAX)
//!        result.append(into_list(a))
//!    print("let cases = ", result, ";")
//! ```

use crate::secp256k1::Num;

/// Assert that adding two numbers returns the expected result.
#[test]
fn addition() {
    let cases = [
        [
            [
                13331687656053523063,
                13660284679052185047,
                6180349862676689476,
                10878281086163749962,
            ],
            [
                15791921640050119461,
                6169422107226388205,
                9683360699919852079,
                11910414196885573702,
            ],
            [
                10676865226689059181,
                1382962712569021637,
                15863710562596541556,
                4341951209339772048,
            ],
        ],
        [
            [
                2462296151734409086,
                3435395525208561589,
                4092672087944524956,
                7478267195873681597,
            ],
            [
                2202999929833192938,
                6111678284273474330,
                4578409370242851888,
                15834227208104735438,
            ],
            [
                4665296085862570297,
                9547073809482035919,
                8671081458187376844,
                4865750330268865419,
            ],
        ],
        [
            [
                10363300866640359417,
                3390337015975975461,
                15763928533502225993,
                14908496793109849911,
            ],
            [
                10796857435490031431,
                535351433247954868,
                3667683284967363857,
                13594199174777287509,
            ],
            [
                2713414232715807505,
                3925688449223930330,
                984867744760038234,
                10055951894177585805,
            ],
        ],
        [
            [
                2863209735998733542,
                9025811689219184168,
                4702069794123924838,
                4503850534435543171,
            ],
            [
                10305327405106205558,
                5763628437104825554,
                13415910842821581480,
                8172999525281327744,
            ],
            [
                13168537141104939100,
                14789440126324009722,
                18117980636945506318,
                12676850059716870915,
            ],
        ],
        [
            [
                6955794984569834090,
                9996284301586176203,
                12563340858036116904,
                11918106765199271042,
            ],
            [
                3232576256857022947,
                5488283155349389550,
                5280550801432941108,
                10116450006716412978,
            ],
            [
                10188371245721825310,
                15484567456935565753,
                17843891659469058012,
                3587812698206132404,
            ],
        ],
        [
            [
                13184982364793954163,
                12932748782376702392,
                12244195654529731276,
                2017440493979963109,
            ],
            [
                5252413477536379957,
                1997494102832052619,
                17304606332570779972,
                2809659401761811154,
            ],
            [
                18437395842330334120,
                14930242885208755011,
                11102057913390959632,
                4827099895741774264,
            ],
        ],
        [
            [
                2061456085547111485,
                3166649711458637888,
                4804476172799257918,
                13999591314433406935,
            ],
            [
                11102924638633885678,
                9932562702068947017,
                14512986866598468452,
                2069940526987684237,
            ],
            [
                13164380724180997163,
                13099212413527584905,
                870718965688174754,
                16069531841421091173,
            ],
        ],
        [
            [
                3522391120954155488,
                10731816473950480939,
                3696841810031818839,
                18061387855154264220,
            ],
            [
                6365085930796809038,
                8963997753472320724,
                5002849004285765662,
                8467644171457276548,
            ],
            [
                9887477056045932799,
                1249070153713250047,
                8699690814317584502,
                8082287952901989152,
            ],
        ],
        [
            [
                1385333823072056757,
                6820602046086836200,
                12616430072798663872,
                16290446681937460534,
            ],
            [
                17109633236122365208,
                17461937034436725430,
                5837309577842519240,
                3776876504514119496,
            ],
            [
                48222989779838622,
                5835795006814010015,
                6995576931631497,
                1620579112742028415,
            ],
        ],
        [
            [
                11915352232203386375,
                4628602453060547544,
                6582734484261290043,
                17389431208464391656,
            ],
            [
                7633279317004517222,
                16770652310685412320,
                5606039858513137981,
                8728306245867429187,
            ],
            [
                1101887479793320254,
                2952510690036408249,
                12188774342774428025,
                7670993380622269227,
            ],
        ],
    ];

    for [a, b, c] in cases {
        let a = Num::new(a);
        let b = Num::new(b);
        let c = Num::new(c);
        assert_eq!(a + b, c);
    }
}

/// Assert that subtracting two numbers returns the expected result.
#[test]
fn subtraction() {
    let cases = [
        [
            [
                5815385562380426701,
                6697839919642350225,
                10751151170854867346,
                14703533146255056436,
            ],
            [
                9003953129462209834,
                7275394214401443547,
                9720760859958817268,
                6584497097961734448,
            ],
            [
                15258176506627768483,
                17869189778950458293,
                1030390310896050077,
                8119036048293321988,
            ],
        ],
        [
            [
                4072409280545219498,
                251996675032523713,
                18298298456457404985,
                9946412455766063459,
            ],
            [
                7062814739027488649,
                16176539252839346137,
                4627291181257267925,
                6456262110698863376,
            ],
            [
                15456338615227282465,
                2522201495902729191,
                13671007275200137059,
                3490150345067200083,
            ],
        ],
        [
            [
                4388484915681691599,
                13430024588273608042,
                2562783154302226387,
                7058659145549261223,
            ],
            [
                3143570946669042265,
                12045106346389195022,
                344299592700309425,
                10697692301120802393,
            ],
            [
                1244913964717681061,
                1384918241884413020,
                2218483561601916962,
                14807710918138010446,
            ],
        ],
        [
            [
                3474215531863306566,
                3782158636696878580,
                7209065058896900750,
                5491389333080330709,
            ],
            [
                17249055279447558235,
                13380481134359385293,
                15685632249252016544,
                9213792950549015524,
            ],
            [
                4671904321830331674,
                8848421576047044902,
                9970176883354435821,
                14724340456240866800,
            ],
        ],
        [
            [
                14808907023618492306,
                4870698351048219766,
                14157050108287638458,
                11575680821689335341,
            ],
            [
                304985802143994189,
                14365398587413688999,
                83003539426496306,
                11740150055923561967,
            ],
            [
                14503921217179529844,
                8952043837344082383,
                14074046568861142151,
                18282274839475324990,
            ],
        ],
        [
            [
                1092899879881191793,
                6030338674085111753,
                4874419348779511299,
                8443978149784998465,
            ],
            [
                9946112429488780627,
                444068910640996323,
                709050609478482803,
                10882036865741267435,
            ],
            [
                9593531519806994509,
                5586269763444115429,
                4165368739301028496,
                16008685357753282646,
            ],
        ],
        [
            [
                5785246591830629601,
                439117672181677603,
                1487496744357098509,
                11287412695519972681,
            ],
            [
                10792490919119489619,
                7114207971479945750,
                5398795175321974494,
                14733134893431824010,
            ],
            [
                13439499742125723325,
                11771653774411283468,
                14535445642744675630,
                15001021875797700286,
            ],
        ],
        [
            [
                17078948541945774971,
                16466601448709170451,
                4076940031544968954,
                6634664142956000276,
            ],
            [
                15000987616608010809,
                6662778076512145167,
                9193965483770982466,
                9903291778675834887,
            ],
            [
                2077960921042795889,
                9803823372197025284,
                13329718621483538104,
                15178116437989717004,
            ],
        ],
        [
            [
                16918546935564386616,
                2908973489490346593,
                16427839170738156564,
                11967915747342581425,
            ],
            [
                14210544028415168456,
                14962161049821650091,
                10704525256921428314,
                8402736542589630298,
            ],
            [
                2708002907149218160,
                6393556513378248118,
                5723313913816728249,
                3565179204752951127,
            ],
        ],
        [
            [
                13864990143584242617,
                17893561488739810340,
                9809303471797789512,
                4769562819942417893,
            ],
            [
                8123338991492548431,
                7583659370082491176,
                9742966507190466257,
                15957433107086756310,
            ],
            [
                5741651147796725913,
                10309902118657319164,
                66336964607323255,
                7258873786565213199,
            ],
        ],
    ];

    for [a, b, c] in cases {
        let a = Num::new(a);
        let b = Num::new(b);
        let c = Num::new(c);
        assert_eq!(a - b, c);
    }
}

/// Assert that multiplying two numbers returns the expected result.
#[test]
fn multiplication() {
    let cases = [
        [
            [
                407506048493619023,
                12986772238221305042,
                9197053217753677061,
                5360739063142725242,
            ],
            [
                10709626626672140135,
                5488372121182707354,
                5187675556658245146,
                1208375431967626380,
            ],
            [
                7748951575618654602,
                4346643880315489253,
                10925727301453237414,
                12886478017469485085,
            ],
        ],
        [
            [
                16245181722914664322,
                5128105247667973715,
                5975974870988265534,
                12915301773443867298,
            ],
            [
                10717603591111123963,
                6951181149983225752,
                10180049170655060196,
                5427232539072539210,
            ],
            [
                7332461624151976369,
                3488051925722004888,
                9735582685621628201,
                1689563475231131459,
            ],
        ],
        [
            [
                796488076587256424,
                6279983558655833849,
                15940131153596030371,
                10678707661442216919,
            ],
            [
                8475367193637173032,
                8879802787374191165,
                3546598830208224260,
                8509096818520445234,
            ],
            [
                9059206614098480415,
                1748094764790177783,
                13787095013775670305,
                1038360926407152661,
            ],
        ],
        [
            [
                7392146803017322354,
                13841505947840798107,
                12140275221284357094,
                9730336969473868583,
            ],
            [
                18349699352476626836,
                8215959497797376200,
                2213734474312751824,
                14327431995474120379,
            ],
            [
                5440379736464249164,
                11698537389535052960,
                2347976563856613617,
                14919546447675144947,
            ],
        ],
        [
            [
                15097296417990508289,
                14969592426845737752,
                9638928961228337584,
                6428298134600772658,
            ],
            [
                12874295240281082873,
                2349574696261709092,
                5092749401819680048,
                17361967001527804608,
            ],
            [
                897555669877052525,
                14724460259274135334,
                2741245073966449253,
                8607909466167803991,
            ],
        ],
        [
            [
                14634277678734506940,
                9278894480091880728,
                2648592110906025855,
                1405247251497846901,
            ],
            [
                17607344427886015407,
                719554634262322710,
                479811560278920541,
                3662158324882821560,
            ],
            [
                17348711304625278314,
                10322674117783219081,
                12483749913190712183,
                3594075498995196521,
            ],
        ],
        [
            [
                11866295277787292433,
                27732823621404771,
                8550034047064244993,
                9476168797223268977,
            ],
            [
                11633001713807579376,
                1081597303322188001,
                15771464389213984608,
                4710057642198374485,
            ],
            [
                18138884047379417694,
                13993097544216429581,
                8694324356829123957,
                8793872340743350750,
            ],
        ],
        [
            [
                2446633146888263200,
                18112540415674385550,
                17370840203561968754,
                11952577779521908265,
            ],
            [
                7979843069226166605,
                7745438226889151008,
                7798725903633117430,
                1150010574403484156,
            ],
            [
                15528046057333424528,
                15703802860669452479,
                11993463058390568653,
                9626171954322032637,
            ],
        ],
        [
            [
                9386736958748712167,
                16686028128813894351,
                629016200001321223,
                17387669111577892150,
            ],
            [
                12424845455732628672,
                6634496564843550903,
                16482098776907985650,
                6438045321802695369,
            ],
            [
                7892930993611959711,
                15057144099263114044,
                9018678829781279818,
                8666088406857067249,
            ],
        ],
        [
            [
                16400121217707915551,
                5096816261426712730,
                12004278960871853687,
                12195971345723098913,
            ],
            [
                8059314425728164294,
                5846520355272976795,
                16812900091502293028,
                300554047156260800,
            ],
            [
                16336979015581825236,
                14862386920722346287,
                1843318059326164007,
                2592443060034273444,
            ],
        ],
    ];

    for [a, b, c] in cases {
        let a = Num::new(a);
        let b = Num::new(b);
        let c = Num::new(c);
        assert_eq!(a * b, c);
    }
}

/// Assert that multiplying a number by its inverse always returns 1.
#[test]
fn inversion() {
    let cases = [
        [
            10952063692820712150,
            4107566514971989675,
            14334172746451041540,
            16336111428691836948,
        ],
        [
            8885601643982555968,
            1235830009073867688,
            2413404478101223216,
            9376798348890460829,
        ],
        [
            1220912414049425853,
            710925936399959688,
            6822351445227917295,
            11404283210801276446,
        ],
        [
            15081497593797694457,
            7429475226282827148,
            18107736455757373996,
            9367974131548068121,
        ],
        [
            12454263801826617321,
            14427593819311627331,
            15278162142380632529,
            11126408260397246704,
        ],
        [
            4630362215105635062,
            10481562963392259073,
            11804179816000837208,
            5032957338784954554,
        ],
        [
            1954942644443772160,
            17488274235857918560,
            9687492386324475034,
            5063317896717153614,
        ],
        [
            17811813398950757199,
            8594373193774048753,
            15442995684055482501,
            7998464193213952589,
        ],
        [
            5683867670395676795,
            13854485491466314800,
            16606183362089968467,
            14284682697879536187,
        ],
        [
            8307730150078357717,
            3483194554963991137,
            11456615319073189620,
            15964813392178852307,
        ],
    ];

    for n in cases {
        let n = Num::new(n);
        assert_eq!(n * n.inv(), Num::ONE);
    }
}
