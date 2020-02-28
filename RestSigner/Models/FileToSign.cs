using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;

namespace RestSigner.Models
{
    [DataContract]
    public class FileToSign
    {
        [DataMember(Name = "name")]
        private string fileName;
        [DataMember(Name = "content")]
        private string encodedFIleContent;

        public string saveFile()
        {
            string path = HttpContext.Current.Server.MapPath("~/App_Data//" + fileName);
            byte[] bufferArray = Convert.FromBase64String(encodedFIleContent);
            File.WriteAllBytes(path, bufferArray);
            //Stream writer = new FileStream(path, FileMode.Create);
            return path;
        }
    }
}