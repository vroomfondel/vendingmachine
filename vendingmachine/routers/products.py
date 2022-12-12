from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from vendingmachine.datastructures.models_and_schemas import (
    Product,
    ProductWithID,
    Seller,
)
from vendingmachine.utils.auth import (
    get_current_user,
    get_current_user_ensure_sellertype,
    responses_401,
    responses_401_404,
)


router = APIRouter(tags=["products"])


@router.get(
    "",
    response_model=List[ProductWithID],
    response_model_exclude_none=True,
    dependencies=[Depends(get_current_user)],
    responses=responses_401,
)
async def get_all_products() -> List[ProductWithID]:
    """gets all products available"""
    products: List[ProductWithID] = await ProductWithID.get_all_products_from_db()
    return products


@router.get(
    "/{product_id}",
    response_model=ProductWithID,
    response_model_exclude_none=True,
    dependencies=[Depends(get_current_user)],
    responses=responses_401_404,
)
async def get_product(product_id: UUID) -> ProductWithID:
    """gets a specific product"""
    product: Optional[ProductWithID] = await ProductWithID.get_product_from_db(product_id)

    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Product with id {product_id} not found.")

    return product


@router.post(
    "",
    response_model=ProductWithID,
    response_model_exclude_none=True,
    status_code=status.HTTP_201_CREATED,
    responses=responses_401 | {403: {"description": "Only Sellers may access this realm."}},
)
async def create_product(
    product_data: Product, seller: Seller = Depends(get_current_user_ensure_sellertype)
) -> ProductWithID:
    """creates a product -> function only available for Sellers"""
    new_product: ProductWithID = ProductWithID(
        seller_id=seller.id,
        amount_available=product_data.amount_available,
        cost=product_data.cost,
        product_name=product_data.product_name,
    )

    new_product = await new_product.create_new()  # shifts to and from DB

    return new_product


@router.put(
    "/{product_id}",
    response_model=ProductWithID,
    response_model_exclude_none=True,
    responses=responses_401 | {403: {"description": "Access to this product not allowed for THIS Seller."}},
)
async def update_product(
    product_id: UUID, product_data: Product, seller: Seller = Depends(get_current_user_ensure_sellertype)
) -> ProductWithID:
    """updates a product -> function only available for Sellers -> only available for the seller who created the product"""
    product: Optional[ProductWithID] = await ProductWithID.get_product_from_db(product_id)
    if not product:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Product with id {product_id} not found.")

    if product.seller_id != seller.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"Product with id {product_id} does not belong to you."
        )

    saved_product: ProductWithID = product.copy(update=product_data.dict())
    await saved_product.save()

    return saved_product


@router.delete(
    "/{product_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=responses_401 | {403: {"description": "Access to this product not allowed for THIS Seller."}},
)
async def delete_product(product_id: UUID, seller: Seller = Depends(get_current_user_ensure_sellertype)) -> None:
    """deletes a product -> function only available for Sellers -> only available for the seller who created the product"""
    product: Optional[ProductWithID] = await ProductWithID.get_product_from_db(product_id)
    if not product:
        raise HTTPException(status_code=status.HTTP_404, detail=f"Product with id {product_id} not found.")

    if product.seller_id != seller.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"Product with id {product_id} does not belong to you."
        )

    await product.delete()
    return None
