namespace Application.Wrappers;

public class Response<T>
{
    public Response()
    {
    }

    public Response(T data, bool succeeded, string message = default!)
    {
        Succeeded = succeeded;
        Message = message;
        Data = data;
    }

    public Response(bool succeeded, string message = default!)
    {
        Succeeded = succeeded;
        Message = message;
    }

    public bool Succeeded { get; set; }

    public string Message { get; set; } = null!;

    public List<string> Errors { get; set; } = null!;

    public T Data { get; set; } = default!;
}