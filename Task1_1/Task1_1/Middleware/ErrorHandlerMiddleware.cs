using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Task1_1.Middleware
{
    
}
public class ErrorHandlerMiddleware
{
    private readonly RequestDelegate _next;

    public ErrorHandlerMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;

        return context.Response.WriteAsync(new
        {
            context.Response.StatusCode,
            Message = "Internal Server Error",
            Detailed = exception.Message
        }.ToString());
    }
}