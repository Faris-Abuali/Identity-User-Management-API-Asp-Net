namespace User.Management.Service.Models;

public class ApiResponse<TResponse>
{
    public bool IsSuccess { get; set; }

    public string? Message { get; set; }

    public int StatusCode { get; set; }
    
    public TResponse? Response { get; set; }
}