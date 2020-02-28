using System;
using System.Collections.Generic;
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
        public void Post([FromBody] FileToSign file)
        {
            file.saveFile();
            string path = HttpContext.Current.Server.MapPath("~/App_Data//idsrv3test.pfx");
            Signer.SignExecutable(path, file.saveFile(), "idsrv3test");
        }
    }
}
