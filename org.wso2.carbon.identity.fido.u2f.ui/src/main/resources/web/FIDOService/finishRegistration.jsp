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
            System.out.println(request.getParameter("tokenResponse"));
            String tokenResponse = request.getParameter("tokenResponse");
            System.out.println(tokenResponse);

            client = new FIDOClient(configContext, serverURL, cookie);
            data = client.finishRegistration(tokenResponse, "admin", "https://testwso2is.com:9443");
            System.out.println(data);
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



<div id="middle">
    <h2>FIDO Registration</h2>

    <div id="workArea">
        <form method="POST" id="form" action="finishRegistration.jsp">
            <table class="styledLeft" id="moduleTable">
                <tr> <h3><%=data%></h3>

                </tr>

                <tr>

                </tr>
             </table>
        </form>
    </div>
</div>