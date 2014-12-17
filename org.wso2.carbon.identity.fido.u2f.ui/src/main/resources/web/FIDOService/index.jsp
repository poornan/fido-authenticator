<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.identity.fido.u2f.ui.FIDOClient" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>
<%
        String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
        ConfigurationContext configContext =
                (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
        String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);

        FIDOClient client;
        String data;
        try {
            client = new FIDOClient(configContext, serverURL, cookie);
            data = client.startRegistration("admin","https://testwso2is.com:9443");
        } catch (Exception e) {
            CarbonUIMessage.sendCarbonUIMessage(e.getMessage(), CarbonUIMessage.ERROR, request, e);
%>
            <script type="text/javascript">
                   location.href = "../admin/error.jsp";
            </script>
<%
            return;
    }
%>
 <script src="chrome-extension://pfboblefjcgdjicmnffhdgionmgcdmne/u2f-api.js"></script>

 <script>
 var request = <%=data%>;
 var loggedInUser =
 setTimeout(function() {
     u2f.register(request.registerRequests, request.authenticateRequests,
     function(data) {
         console.log(data);
         var form = document.getElementById('form');
         var reg = document.getElementById('tokenResponse');
         if(data.errorCode) {
             alert("U2F failed with error: " + data.errorMessage);
             return;
         }
         reg.value=JSON.stringify(data);
         form.submit();
     });
 }, 10000);
 </script>

<div id="middle">
    <h2>FIDO Registration</h2>

    <div id="workArea">
        <form method="POST" id="form" action="finishRegistration.jsp">
            <table class="styledLeft" id="moduleTable">
                <tr> <h3>Touch your U2F token.</h3>
                    <input type="hidden" name="username" id="username"/>
                    <input type="hidden" id="tokenResponse" name="tokenResponse"/>
                </tr>

                <tr>

                </tr>
             </table>
        </form>
    </div>
</div>