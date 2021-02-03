<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>

<!DOCTYPE html>
<html>
	<head>
		<title>luv2code Company Home Page</title>
	</head>
	<body>
		<h2>luv2code Company Home Page</h2>
		<br />
		<p>
			Welcome to the luv2code Company Home Page
		</p>
		
		<hr />
			<!-- Display username and role -->
			<p>
				User: <security:authentication property="principal.username" />
				<br /><br />
				Role(s): <security:authentication property="principal.authorities" />
			</p>
		<hr />
		
		<security:authorize access="hasRole('MANAGER')">
			<!-- Add a link to point to /leaders for the MANAGERS -->
			<p>
				<a href="${pageContext.request.contextPath}/leaders">Leadership Meeting</a>
				(Only for Managers)
			</p>
		
			<hr />
		</security:authorize>
		
		<security:authorize access="hasRole('ADMIN')">
			<!-- Add a link to point to /systems only for ADMINS -->
			<p>
				<a href="${pageContext.request.contextPath}/systems">IT Systems Meeting</a>
				(Only for Admins)
			</p>
		
			<hr />
		</security:authorize>
		
		<!-- Add a logout button -->
		<form:form action="${pageContext.request.contextPath}/logout" method="POST">
		
			<input type="submit" value="Logout" />
			
		</form:form>
		
	</body>
</html>