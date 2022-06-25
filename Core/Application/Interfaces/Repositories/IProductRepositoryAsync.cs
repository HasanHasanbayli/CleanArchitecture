namespace Application.Interfaces.Repositories;

public interface IProductRepositoryAsync
{
    Task<bool> IsUniqueBarcodeAsync(string barcode);
}