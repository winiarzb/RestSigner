using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using RestSigner.Models;

namespace RestSigner.Controllers
{
    public class SignController : ApiController
    {
        // POST: api/Sign
        public HttpResponseMessage Post([FromBody] FileToSign file)
        {
            string path = file.saveFile();
            // string path = HttpContext.Current.Server.MapPath("~/App_Data//idsrv3test.pfx");
            Signer signer = new Signer();
            // signer.SignExecutable(@"C:\Users\boi137\Desktop\SOD_Setup.msi");
            signer.SignExecutable(path, "12345678");

            file.updateContent(path);
            // byte[] bufferArray = File.ReadAllBytes(path);
            // string base64EncodedString = Convert.ToBase64String(bufferArray);
            var message = Request.CreateResponse(HttpStatusCode.OK, file);

            return message;
        }
    }
}
