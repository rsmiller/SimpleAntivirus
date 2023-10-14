using Couchbase.Lite;
using Couchbase.Lite.Query;
using OfficeOpenXml;
using System.Security.Cryptography;
using System.Text;
using dnYara;
using System.Data;
using dnYara.Exceptions;

// Info:
// This started as a weekend project to find practical ways to apply what I've learned over the last few months
//
// Excel file is a compiled from a csv that came from a full malware hash database from Malware Bazaar located at https://bazaar.abuse.ch/export/
// 
// I had never used couchbase lite before and thought it would be neat to test. Not all that impressed and will have to find a different db.
//   - The encyption seems to be only enterprise available and its weird that the "file" is recognized as a folder.
//
// Yar files will have to be combined into an encypted binary, or is the local db can handle json...
// 
// Need to add:
//   - Mechananisms for EDR
//      - Embeeded organizational attributes
//      - Send telemetry data to Elastic
//      - Ability to download and apply new malware yar and hashes


// Global vars

Database malware_db = null;
Collection malware_collection = null;
Collection scan_collection = null;

YaraContext yara = new YaraContext();
CompiledRules yara_rules = null;
Scanner yara_scanner = new Scanner();


Main();


///////////////////////////////////////////////////////////////////////
void Main()
{
    Console.ForegroundColor = ConsoleColor.White;

    Precheck();
    BeginScan();

    malware_db?.Close();
}


void Precheck()
{
    if(!Database.Exists("malwaredb", Environment.CurrentDirectory))
    {
        // At first run we will create the couchbase lite database

        malware_db = new Database("malwaredb", new DatabaseConfiguration
        {
            Directory = Environment.CurrentDirectory,
        });

        malware_collection = malware_db.GetDefaultCollection();

        Console.WriteLine("Creating database from first run. Please wait...");

        // We are going to start to build the malware database
        SaveHashesFromMalewareBazaar();
    }

    if(malware_db == null)
    {
        malware_db = new Database("malwaredb", new DatabaseConfiguration
        {

            Directory = Environment.CurrentDirectory,
        });


        malware_collection = malware_db.GetDefaultCollection();

        Console.WriteLine("Database initialized");
    }

    // Not the best way of doing this for security reasons but for a demo I've put a few yara rules in a folder
    var rule_files = Directory.GetFiles(Environment.CurrentDirectory + @"\rules\", "*.yar", SearchOption.AllDirectories).ToArray();


    using (var compiler = new Compiler())
    {
        foreach (var yara in rule_files)
            compiler.AddRuleFile(yara);

        yara_rules = compiler.Compile();

        Console.WriteLine("Rules initialized");
    }
}

void BeginScan()
{
    DoDriveScanning();
    DoRAMScanning();
    DoRegScanning();
    DoProcessScanning();
}

void DoDriveScanning()
{
    // Single threaded checking because this is an example
    // Going to check just the main drive because this is a demo
    var main_drive = DriveInfo.GetDrives().Where(m => m.IsReady == true && m.Name == "C:\\").FirstOrDefault();

    if (main_drive != null)
    {
        var root_dir = main_drive.RootDirectory;

        CheckFiles(root_dir);
    }
}


void DoRAMScanning()
{
    // Look for IOCs in RAM
}

void DoRegScanning()
{
    // Look for IOCs in the Registry
}

void DoProcessScanning()
{
    // Look for IOCs in the processes
}

void CheckFiles(DirectoryInfo current_dir)
{
    try
    {
        // Not going to check archival media in the example
        foreach (var file in current_dir.EnumerateFiles().Where(m => (m.Extension == ".exe" || m.Extension == ".dll" || m.Extension == ".sys")))
        {
            Console.WriteLine(file.FullName);

            var file_hash = GetSha256Hash(file.FullName);

            // Debug code to test a match
            //CheckFileHash(file.FullName, " e89071c2cad535d359a460c089f939a68a9faf480f9d1e0ea4134cfc77763748"); 

            CheckFileHash(file.FullName, file_hash); // Checking that hash
            CheckFileYara(file.FullName); // Checking that string data
        }

        foreach (var dir in current_dir.EnumerateDirectories())
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(dir.FullName);
            Console.ForegroundColor = ConsoleColor.White;

            CheckFiles(dir);
        }
    }
    catch(UnauthorizedAccessException)
    {
        // Feeling unwanted
    }
}


void CheckFileHash(string file_path, string file_hash)
{
    // Find hash
    var query = QueryBuilder.Select(SelectResult.All()).From(DataSource.Collection(malware_collection))
                            .Where(Expression.Property("sha256_hash").EqualTo(Expression.String(file_hash.ToLower())));

    var query_result = query.Execute().AllResults().FirstOrDefault();

    if (query_result != null)
    {
        var dic = query_result.GetDictionary(0);
        QuarantineFile(file_path, dic.GetString("signature"));
    }
}

void CheckFileYara(string file_path)
{
    try
    {
        var scan_results = yara_scanner.ScanFile(file_path, yara_rules);

        if (scan_results.Count() > 0)
        {
            var do_first_match = scan_results.First();
            QuarantineFile(file_path, scan_results[0].MatchingRule.Identifier); // 
        }
    }
    catch(YaraException)
    {
        // No one wants to play
    }
}

void QuarantineFile(string file_path, string malware_name)
{
    // Move it somewhere
    // Probably check the file extention
    // Probably kill any processes it is running

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("OMG WE FOUND " + malware_name);
    Console.ForegroundColor = ConsoleColor.White;
}


void SaveHashesFromMalewareBazaar()
{
    var index = IndexBuilder.ValueIndex(ValueIndexItem.Expression(Expression.Property("sha256_hash")));

    malware_collection.CreateIndex("sha256_hash_idx", index);

    
    ExcelPackage.LicenseContext = LicenseContext.NonCommercial;

    // Read from sheet
    using (var sourcePackage = new ExcelPackage(new FileInfo(Environment.CurrentDirectory + @"\all_the_bad_things.xlsx")))
    {
        var ws = sourcePackage.Workbook.Worksheets[0];

        var start = ws.Dimension.Start;
        var end = ws.Dimension.End;

        for (int row = start.Row + 1; row <= end.Row; row++)
        {
            var doc = new MutableDocument();
            doc.SetString("sha256_hash", ws.Cells[row, 1].Value.ToString());
            doc.SetString("sha1_hash", ws.Cells[row, 3].Value.ToString());
            doc.SetString("md5_hash", ws.Cells[row, 2].Value.ToString());
            doc.SetString("file_name", GetValue(ws.Cells[row, 4].Value));
            doc.SetString("file_type", GetValue(ws.Cells[row, 5].Value));
            doc.SetString("signature", GetValue(ws.Cells[row, 6].Value));


            malware_collection.Save(doc);

            Console.Clear();
            Console.WriteLine("Building the local malware database from https://bazaar.abuse.ch/export/ excel file....");
            Console.Write(row + "/" + end.Row + "\n");
        }
    }
}


string GetValue(object obj)
{
    try
    {
        if (obj != null)
            return (string)obj;
        else
            return "";
    }
    catch(Exception) { return ""; }
}

string GetSha256Hash(string filePath)
{
    try
    {
        using (var sha = SHA256.Create())
        {
            using (FileStream fileStream = File.OpenRead(filePath))
                return ByteArrayToHex(sha.ComputeHash(fileStream));
        }
    }
    catch (Exception) { return ""; }
}

string ByteArrayToHex(byte[] buffer)
{
    StringBuilder hex = new StringBuilder(buffer.Length * 2);

    foreach (byte b in buffer)
        hex.AppendFormat("{0:x2}", b);

    return hex.ToString();
}